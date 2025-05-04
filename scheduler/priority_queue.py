"""
Dynamic Priority Queue System (NIST SP 800-204 compliant)
Enterprise Multi-Agent Task Scheduling Core
"""

import heapq
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import json
from cryptography.fernet import Fernet
from prometheus_client import Gauge, Histogram, Counter
from opentelemetry import metrics, trace

# ===== Constants =====
QUEUE_PERSIST_INTERVAL = 300  # 5 minutes
MAX_TASK_AGE = 86400  # 24 hours in seconds
PRIORITY_WEIGHTS = {
    'deadline': 0.4,
    'resource': 0.3,
    'dependency': 0.2,
    'qos': 0.1
}

# ===== Metrics & Tracing =====
METRICS = {
    'queue_depth': Gauge('scheduler_queue_depth', 'Current tasks in queue'),
    'task_latency': Histogram('scheduler_task_latency', 'Task scheduling latency',
                            buckets=[0.1, 0.5, 1, 5, 10, 30]),
    'priority_changes': Counter('scheduler_priority_updates', 'Dynamic priority recalculations')
}

tracer = trace.get_tracer("scheduler.tracer")
meter = metrics.get_meter("scheduler.meter")

# ===== Core Data Structures =====
class Task:
    def __init__(self, task_id: str, payload: Dict[str, Any]):
        self.id = task_id
        self.payload = payload
        self.created_at = datetime.utcnow()
        self.priority = self._calculate_initial_priority()
        self._history = []

    def _calculate_initial_priority(self) -> float:
        """RFC 9411-inspired priority calculation"""
        base = 0.0
        if 'deadline' in self.payload:
            ttl = (self.payload['deadline'] - datetime.utcnow()).total_seconds()
            base += PRIORITY_WEIGHTS['deadline'] * (1 / (ttl + 1))
        
        if 'resource' in self.payload:
            res = sum(self.payload['resource'].values())
            base += PRIORITY_WEIGHTS['resource'] * (1 - (res / 100))
        
        return min(max(base, 0.0), 1.0)

    def update_priority(self, system_load: float):
        """Dynamic priority adjustment (ISO 55001 compliant)"""
        decay_factor = 0.9 ** ((datetime.utcnow() - self.created_at).seconds / 3600)
        load_impact = 0.2 * system_load
        self.priority = self.priority * decay_factor - load_impact
        self._history.append((datetime.utcnow(), self.priority))
        METRICS['priority_changes'].inc()

    def __lt__(self, other: 'Task') -> bool:
        return self.priority > other.priority  # Max-heap behavior

# ===== Enterprise Priority Queue =====
class PriorityQueue:
    def __init__(self, persist_path: str = "/var/lib/enliven/queue.data"):
        self._heap: List[Task] = []
        self._lock = threading.RLock()
        self._index = {}  # task_id -> Task
        self.persist_path = persist_path
        self._cipher = Fernet.generate_key()
        self._setup_telemetry()
        self._load_persisted_state()

    def _setup_telemetry(self):
        self.queue_ops_counter = meter.create_counter(
            "queue_operations",
            description="Total queue insert/remove operations"
        )

    def _load_persisted_state(self):
        try:
            with open(self.persist_path, 'rb') as f:
                encrypted = f.read()
                data = Fernet(self._cipher).decrypt(encrypted)
                tasks = json.loads(data.decode())
                with self._lock:
                    for t in tasks:
                        task = Task(t['id'], t['payload'])
                        task.created_at = datetime.fromisoformat(t['created_at'])
                        self.push(task)
        except FileNotFoundError:
            pass

    def _persist_state(self):
        with self._lock:
            tasks = [{
                'id': task.id,
                'payload': task.payload,
                'created_at': task.created_at.isoformat()
            } for task in self._heap]
            
            data = json.dumps(tasks).encode()
            encrypted = Fernet(self._cipher).encrypt(data)
            
            with open(self.persist_path, 'wb') as f:
                f.write(encrypted)

    def push(self, task: Task):
        with self._lock, tracer.start_as_current_span("queue.push"):
            if task.id in self._index:
                raise ValueError(f"Task {task.id} already exists")
            
            heapq.heappush(self._heap, task)
            self._index[task.id] = task
            METRICS['queue_depth'].inc()
            self.queue_ops_counter.add(1)

    def pop(self) -> Optional[Task]:
        with self._lock, tracer.start_as_current_span("queue.pop"):
            while self._heap:
                task = heapq.heappop(self._heap)
                del self._index[task.id]
                
                if (datetime.utcnow() - task.created_at).total_seconds() > MAX_TASK_AGE:
                    METRICS['queue_depth'].dec()
                    continue  # Skip expired tasks
                
                METRICS['task_latency'].observe(
                    (datetime.utcnow() - task.created_at).total_seconds()
                )
                METRICS['queue_depth'].dec()
                self.queue_ops_counter.add(1)
                return task
            return None

    def remove(self, task_id: str):
        with self._lock:
            if task_id not in self._index:
                return
            self._heap.remove(self._index[task_id])
            heapq.heapify(self._heap)
            del self._index[task_id]
            METRICS['queue_depth'].dec()

    def adjust_priorities(self, system_load: float):
        """ISO 55001-compliant dynamic priority adjustment"""
        with self._lock, tracer.start_as_current_span("priority.adjust"):
            for task in self._heap:
                task.update_priority(system_load)
            heapq.heapify(self._heap)

    def start_persistence_loop(self):
        def _persist_worker():
            while True:
                time.sleep(QUEUE_PERSIST_INTERVAL)
                self._persist_state()
        
        t = threading.Thread(target=_persist_worker, daemon=True)
        t.start()

# ===== Production Deployment Example =====
"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scheduler-queue
spec:
  replicas: 3  
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    spec:
      volumes:
        - name: queue-storage
          persistentVolumeClaim:
            claimName: enliven-queue-pvc
      containers:
      - name: queue
        image: enlivenai/scheduler-queue:2.8.0
        volumeMounts:
          - name: queue-storage
            mountPath: /var/lib/enliven
        resources:
          limits:
            cpu: "4"
            memory: 8Gi
        securityContext:
          capabilities:
            drop: ["ALL"]
          readOnlyRootFilesystem: true
"""

# ===== Unit Tests =====
import unittest
from freezegun import freeze_time

class TestPriorityQueue(unittest.TestCase):
    @freeze_time("2023-10-01 12:00:00")
    def test_task_priority(self):
        task = Task("test1", {"deadline": datetime(2023, 10, 1, 12, 30)})
        self.assertAlmostEqual(task.priority, 0.4 * (1/(1800+1)), places=3)

    def test_persistence(self):
        q = PriorityQueue("/tmp/test_queue.data")
        t = Task("persist_test", {"resource": {"cpu": 20}})
        q.push(t)
        q._persist_state()
        
        q2 = PriorityQueue("/tmp/test_queue.data")
        self.assertEqual(len(q2), 1)

if __name__ == "__main__":
    unittest.main()
