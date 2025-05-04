"""
Enliven AGENT Core API (v3.2.0)
REST API for Autonomous Agent Management
ISO/IEC 27034 | NIST AI RMF
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, EmailStr, validator
from typing import List, Optional, Annotated
from datetime import datetime, timedelta
import logging
import uuid

# Security & Auth
from security.oauth2 import OAuth2PasswordBearerWithCookie
from security.mtls_handler import validate_client_cert
from security.role_manager import RBAC

# Database
from sqlalchemy.orm import Session
from database.session import get_db
from database.models import Agent, AgentState

# Monitoring
from opentelemetry import trace
from prometheus_client import Counter, Histogram

router = APIRouter(prefix="/v1/agents", tags=["agent_management"])

# --- Security Definitions ---
oauth2_scheme = OAuth2PasswordBearerWithCookie(
    tokenUrl="/v1/auth/token",
    scopes={
        "agent:read": "Read agent information",
        "agent:write": "Modify agent configuration",
        "agent:admin": "Full agent lifecycle control"
    }
)

# --- Metrics & Tracing ---
AGENT_OPS_COUNTER = Counter(
    'agent_operations_total',
    'Total agent operations',
    ['operation', 'agent_type']
)
AGENT_LATENCY = Histogram(
    'agent_api_latency_seconds',
    'API latency distribution',
    ['endpoint', 'method']
)
tracer = trace.get_tracer("agent.provider")

# --- Models ---
class AgentBase(BaseModel):
    name: str = Field(..., min_length=3, max_length=50, 
                     regex="^[a-zA-Z0-9_-]+$")
    agent_type: str = Field(..., alias="type",
                          enum=["cognitive", "actuator", "sensor", "orchestrator"])
    description: Optional[str] = Field(None, max_length=500)
    owner_email: EmailStr
    runtime_profile: str = Field("default", min_length=3)

    @validator('runtime_profile')
    def validate_profile(cls, v):
        allowed_profiles = ["default", "high-mem", "gpu-accelerated", "low-latency"]
        if v not in allowed_profiles:
            raise ValueError(f"Invalid runtime profile. Allowed: {allowed_profiles}")
        return v

class AgentCreate(AgentBase):
    initial_config: dict = Field(
        default_factory=lambda: {"priority": 50, "max_retries": 3}
    )

class AgentResponse(AgentBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    current_state: str
    version: str

    class Config:
        orm_mode = True

# --- Core Services ---
@router.post(
    "/",
    response_model=AgentResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RBAC(required_roles=["admin"]))]
)
async def create_agent(
    agent: AgentCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(oauth2_scheme),
    client_cert: dict = Depends(validate_client_cert)
):
    """Create new autonomous agent with secure bootstrap process"""
    with tracer.start_as_current_span("create_agent"):
        AGENT_OPS_COUNTER.labels("create", agent.agent_type).inc()
        
        db_agent = Agent(
            **agent.dict(exclude={"initial_config"}),
            state=AgentState(
                config=agent.initial_config,
                current_status="provisioning"
            ),
            created_by=current_user["sub"],
            tenant_id=current_user["tenant"]
        )

        try:
            db.add(db_agent)
            db.commit()
            db.refresh(db_agent)
            
            # Async initialization workflow
            await _trigger_provisioning_workflow(db_agent.id)
            
            return db_agent
        except Exception as exc:
            db.rollback()
            logging.error(f"Agent creation failed: {str(exc)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Agent provisioning failed"
            )

@router.get("/{agent_id}", response_model=AgentResponse,
           dependencies=[Depends(RBAC(required_scopes=["agent:read"]))])
def get_agent(
    agent_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(oauth2_scheme)
):
    """Retrieve agent details with authorization checks"""
    with tracer.start_as_current_span("get_agent"):
        AGENT_OPS_COUNTER.labels("read", "any").inc()
        
        db_agent = db.query(Agent).filter(
            Agent.id == agent_id,
            Agent.tenant_id == current_user["tenant"]
        ).first()

        if not db_agent:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Agent not found"
            )
            
        return db_agent

# --- Internal Methods ---
async def _trigger_provisioning_workflow(agent_id: uuid.UUID):
    """Initiate secure agent provisioning workflow"""
    from workflows.provisioning import start_agent_provisioning
    from message_broker import publish_provisioning_event
    
    try:
        # Publish to message broker
        await publish_provisioning_event({
            "agent_id": str(agent_id),
            "timestamp": datetime.utcnow().isoformat(),
            "initiator": "api-service"
        })
        
        # Start async workflow
        await start_agent_provisioning(agent_id)
    except Exception as exc:
        logging.critical(f"Provisioning workflow failed: {exc}")
        raise

# --- Health Check ---
@router.get("/health", include_in_schema=False)
def health_check():
    return {
        "status": "operational",
        "version": "3.2.0",
        "timestamp": datetime.utcnow().isoformat()
    }

# --- Error Handlers ---
@router.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    logging.warning(f"API Exception: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers
    )
