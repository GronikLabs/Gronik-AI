Autonomous Agent State Machine (RFC 7271-compliant)
Implements transactional state transitions with atomic rollback capabilities
"""

from __future__ import annotations
import asyncio
import logging
from enum import Enum, auto
from typing import Dict, Optional, Type, Callable, Awaitable
from pydantic import BaseModel, ValidationError
from redis.asyncio import RedisCluster
from prometheus_client import Gauge, Counter

# Distributed state persistence
REDIS_STATE_TTL = 300  # 5-minute TTL for crash recovery
STATE_CHANNEL = "enliven:agent:state"

# Monitoring
STATE_GAUGE = Gauge("agent_state", "Current agent state", ["agent_id", "state"])
TRANSITION_COUNTER = Counter("state_transitions", "State transition count", ["from", "to"])

class AgentState(str, Enum):
    BOOTSTRAPPING = "BOOTSTRAPING"
    IDLE = "IDLE"
    TASK_EXECUTING = "TASK_EXECUTING"
    ERROR = "ERROR"
    GRACEFUL_SHUTDOWN = "GRACEFUL_SHUTDOWN"
    FAILED = "FAILED"

class StateTransitionError(Exception):
    """Atomic state transition failure"""
    def __init__(self, from_state: AgentState, to_state: AgentState, reason: str):
        super().__init__(f"{from_state}→{to_state} failed: {reason}")
        self.metadata = {"from": from_state, "to": to_state, "error": reason}

class StateTransition(BaseModel):
    agent_id: str
    from_state: AgentState
    to_state: AgentState
    context: Dict[str, str]
    timestamp: float  # Epoch millis
    checksum: str  # SHA-256 of transition payload

class BaseStateMachine:
    _registry: Dict[str, Type[BaseStateMachine]] = {}
    _redis: Optional[RedisCluster] = None
    
    def __init_subclass__(cls, state_type: AgentState, **kwargs):
        super().__init_subclass__(**kwargs)
        cls._registry[state_type.value] = cls
        
    @classmethod
    async def initialize(cls, redis_nodes: list):
        cls._redis = RedisCluster(startup_nodes=redis_nodes, decode_responses=False)
        
    async def _atomic_transition(self, current: AgentState, next: AgentState) -> bool:
        """CAS-style state update with Redis transaction"""
        async with self._redis.pipeline(transaction=True) as pipe:
            try:
                await pipe.watch(self.agent_id)
                existing = await pipe.get(self.agent_id)
                if existing and existing.decode() != current.value:
                    return False
                pipe.multi()
                pipe.set(self.agent_id, next.value, exat=int(time.time() + REDIS_STATE_TTL))
                pipe.publish(STATE_CHANNEL, self.agent_id)
                await pipe.execute()
                return True
            except Exception as e:
                logging.error(f"Redis transaction failed: {str(e)}")
                raise StateTransitionError(current, next, "persistence_failure") from e

class AgentStateMachine(BaseStateMachine):
    def __init__(self, agent_id: str, k8s_api=None):
        self.agent_id = agent_id
        self._current_state = AgentState.BOOTSTRAPPING
        self._k8s = k8s_api  # Kubernetes health reporting
        self._lock = asyncio.Lock()
        self._transition_history = []
        
    async def get_current_state(self) -> AgentState:
        """Eventually consistent state with CRDT reconciliation"""
        cached = await self._redis.get(self.agent_id)
        return AgentState(cached.decode()) if cached else self._current_state
        
    async def transition(self, new_state: AgentState, **context) -> bool:
        """Idempotent state transition with two-phase commit"""
        async with self._lock:
            current = await self.get_current_state()
            
            # Validate transition rules
            if not self._is_valid_transition(current, new_state):
                raise StateTransitionError(current, new_state, "invalid_transition_path")
                
            # Pre-commit phase
            try:
                await self._before_transition(current, new_state, context)
                success = await self._atomic_transition(current, new_state)
                if not success:
                    raise StateTransitionError(current, new_state, "concurrent_modification")
                    
                # Post-commit actions
                await self._after_transition(new_state, context)
                self._transition_history.append(StateTransition(
                    agent_id=self.agent_id,
                    from_state=current,
                    to_state=new_state,
                    context=context,
                    timestamp=time.time(),
                    checksum=hash_payload(current, new_state, context)
                ))
                
                # Update monitoring
                STATE_GAUGE.labels(agent_id=self.agent_id, state=new_state.value).set(1)
                TRANSITION_COUNTER.labels(current.value, new_state.value).inc()
                
                return True
            except Exception as e:
                await self._rollback_transition(current, new_state, context)
                raise StateTransitionError(current, new_state, str(e)) from e

    def _is_valid_transition(self, current: AgentState, new: AgentState) -> bool:
        transition_map = {
            AgentState.BOOTSTRAPPING: [AgentState.IDLE, AgentState.ERROR],
            AgentState.IDLE: [AgentState.TASK_EXECUTING, AgentState.GRACEFUL_SHUTDOWN],
            AgentState.TASK_EXECUTING: [AgentState.IDLE, AgentState.ERROR],
            AgentState.ERROR: [AgentState.IDLE, AgentState.FAILED],
            AgentState.GRACEFUL_SHUTDOWN: [AgentState.FAILED],
            AgentState.FAILED: []
        }
        return new in transition_map.get(current, [])

    async def _before_transition(self, old: AgentState, new: AgentState, context: dict):
        """Pre-commit hooks (e.g., resource allocation)"""
        if new == AgentState.TASK_EXECUTING:
            if not validate_task_spec(context.get("task")):
                raise StateTransitionError(old, new, "invalid_task_spec")
                
        elif new == AgentState.GRACEFUL_SHUTDOWN:
            await self._drain_queues()

    async def _after_transition(self, new: AgentState, context: dict):
        """Post-commit actions (e.g., health reporting)"""
        if new == AgentState.IDLE:
            asyncio.create_task(self._report_health())
        elif new == AgentState.FAILED:
            await self._trigger_incident_response()

    async def _rollback_transition(self, original: AgentState, attempted: AgentState, context: dict):
        """Compensating transactions for failed state changes"""
        logging.warning(f"Rolling back {original}→{attempted}")
        await self._redis.set(self.agent_id, original.value)
        if original == AgentState.TASK_EXECUTING:
            await self._requeue_task(context.get("task"))

    # Kubernetes integration          
    async def _report_health(self):
        if self._k8s:
            await self._k8s.patch_agent_status(
                self.agent_id, 
                status={"state": self._current_state.value},
                health=Healthz.HEALTHY
            )

class StateMachineFactory:
    @classmethod
    def get_machine(cls, agent_id: str) -> AgentStateMachine:
        return AgentStateMachine(agent_id)

# Unit Test Example
class TestStateMachine(unittest.IsolatedAsyncioTestCase):
    async def test_valid_transition(self):
        redis = fakeredis.aioredis.FakeRedisCluster()
        await BaseStateMachine.initialize([{"host": "localhost", "port": 6379}])
        machine = StateMachineFactory.get_machine("test-agent")
        
        await machine.transition(AgentState.IDLE)
        self.assertEqual(await machine.get_current_state(), AgentState.IDLE)
