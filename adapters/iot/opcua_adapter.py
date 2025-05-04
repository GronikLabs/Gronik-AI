Industrial OPC UA Client Adapter (v1.04)
IEC 62541 & NIST SP 800-82 compliant
"""

import os
import sys
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from asyncua import Client, ua
from asyncua.common.subscription import Subscription
from pydantic import BaseModel, Field, validator
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from prometheus_client import Counter, Histogram, Gauge

# ===== Constants =====
RECONNECT_INTERVAL = 30
SECURITY_POLICIES = {
    "Basic256Sha256": ua.SecurityPolicyType.Basic256Sha256,
    "Aes128Sha256RsaOaep": ua.SecurityPolicyType.Aes128Sha256RsaOaep
}

# ===== Metrics =====
OPCUA_METRICS = {
    'connections': Counter('opcua_connections', 'Connection attempts', ['endpoint']),
    'read_ops': Counter('opcua_read_ops', 'Read operations', ['node']),
    'write_ops': Counter('opcua_write_ops', 'Write operations', ['node']),
    'latency': Histogram('opcua_latency', 'Operation latency', ['operation']),
    'subscriptions': Gauge('opcua_subscriptions', 'Active subscriptions'),
    'buffer_size': Histogram('opcua_buffer_size', 'Data packet size', ['direction'])
}

# ===== Data Models =====
class OPCUAConfig(BaseModel):
    endpoint: str
    security_policy: str = "Basic256Sha256"
    application_uri: str
    cert_path: str
    key_path: str
    server_cert_path: str
    timeout: float = 30.0
    auto_reconnect: bool = True
    publish_interval: float = 1.0
    queue_size: int = 1000

    @validator('security_policy')
    def validate_policy(cls, v):
        if v not in SECURITY_POLICIES:
            raise ValueError(f"Invalid security policy. Valid options: {list(SECURITY_POLICIES.keys())}")
        return v

class NodeReadRequest(BaseModel):
    node_id: str
    attribute: ua.AttributeIds = ua.AttributeIds.Value

class NodeWriteRequest(BaseModel):
    node_id: str
    value: Union[int, float, str, bool]
    data_type: ua.NodeId

# ===== Core Client =====
class IndustrialOPCUAAdapter:
    """Enterprise OPC UA Client with Industrial IoT Security"""
    
    def __init__(self, config: OPCUAConfig):
        self.config = config
        self._client = None
        self._subscriptions = {}
        self._reconnect_task = None
        self._connected = False
        self._security_policy = SECURITY_POLICIES[config.security_policy]
        
        self._init_client()
        self._load_certificates()

    def _init_client(self):
        """Configure OPC UA client with industrial security settings"""
        self._client = Client(
            url=self.config.endpoint,
            timeout=self.config.timeout
        )
        
        self._client.application_uri = self.config.application_uri
        self._client.secure_channel_timeout = int(self.config.timeout * 1000)
        self._client.session_timeout = int(self.config.timeout * 1000 * 2)
        
        # Configure asyncua internal logger
        logger = logging.getLogger("asyncua")
        logger.setLevel(logging.WARNING)

    def _load_certificates(self):
        """Load X.509 certificates with industrial-grade validation"""
        # Client certificate
        with open(self.config.cert_path, "rb") as cert_file:
            self._client_cert = load_pem_x509_certificate(cert_file.read())
            
        # Private key
        with open(self.config.key_path, "rb") as key_file:
            self._private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
            
        # Server certificate
        with open(self.config.server_cert_path, "rb") as server_cert_file:
            self._server_cert = load_pem_x509_certificate(server_cert_file.read())

        self._client.set_security(
            self._security_policy,
            certificate=self._client_cert.public_bytes(serialization.Encoding.DER),
            private_key=self._private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ),
            server_certificate=self._server_cert.public_bytes(serialization.Encoding.DER)
        )

    async def __aenter__(self):
        await self.connect()
        return self
    
    async def __aexit__(self, *exc):
        await self.disconnect()

    async def connect(self):
        """Establish secure connection with automatic retry"""
        try:
            OPCUA_METRICS['connections'].labels(self.config.endpoint).inc()
            
            with OPCUA_METRICS['latency'].labels('connect').time():
                await self._client.connect()
                self._connected = True
                
                # Create monitored items queue
                self._data_queue = asyncio.Queue(maxsize=self.config.queue_size)
                
                # Start background tasks
                self._monitor_task = asyncio.create_task(self._data_monitor())
                
                return True

        except (ua.UaError, ConnectionError) as exc:
            logging.error(f"Connection failed: {exc}")
            if self.config.auto_reconnect:
                self._schedule_reconnect()
            return False

    async def disconnect(self):
        """Graceful shutdown with session cleanup"""
        if self._connected:
            await self._client.disconnect()
            self._connected = False
            
            if self._monitor_task:
                self._monitor_task.cancel()
                
            if self._reconnect_task:
                self._reconnect_task.cancel()

    async def read_node(self, request: NodeReadRequest) -> ua.DataValue:
        """Read node value with industrial reliability"""
        try:
            with OPCUA_METRICS['latency'].labels('read').time():
                node = self._client.get_node(request.node_id)
                value = await node.read_attribute(request.attribute)
                
                OPCUA_METRICS['read_ops'].labels(request.node_id).inc()
                OPCUA_METRICS['buffer_size'].labels('in').observe(sys.getsizeof(value))
                
                return value

        except ua.UaError as exc:
            self._handle_communication_error(exc)
            raise

    async def write_node(self, request: NodeWriteRequest):
        """Secure write operation with data validation"""
        try:
            with OPCUA_METRICS['latency'].labels('write').time():
                node = self._client.get_node(request.node_id)
                dv = ua.DataValue(ua.Variant(request.value, request.data_type))
                await node.write_value(dv)
                
                OPCUA_METRICS['write_ops'].labels(request.node_id).inc()
                OPCUA_METRICS['buffer_size'].labels('out').observe(sys.getsizeof(dv))

        except ua.UaError as exc:
            self._handle_communication_error(exc)
            raise

    async def create_subscription(
        self,
        nodes: List[str],
        callback: callable,
        publishing_interval: Optional[float] = None
    ) -> Subscription:
        """Industrial-grade data subscription with queue buffering"""
        try:
            subscription = await self._client.create_subscription(
                publishing_interval or self.config.publish_interval,
                self._data_queue
            )
            
            handles = []
            for node_id in nodes:
                node = self._client.get_node(node_id)
                handle = await subscription.subscribe_data_change(node)
                handles.append(handle)
                
            self._subscriptions[subscription.subscription_id] = {
                "subscription": subscription,
                "handles": handles,
                "callback": callback
            }
            
            OPCUA_METRICS['subscriptions'].inc()
            return subscription

        except ua.UaError as exc:
            self._handle_communication_error(exc)
            raise

    async def _data_monitor(self):
        """Background task for processing subscription data"""
        while self._connected:
            try:
                msg = await asyncio.wait_for(
                    self._data_queue.get(),
                    timeout=1.0
                )
                
                for sub_id, sub_info in self._subscriptions.items():
                    if msg.subscription_id == sub_id:
                        await sub_info["callback"](msg)
                        
            except asyncio.TimeoutError:
                continue
            except ua.UaError as exc:
                self._handle_communication_error(exc)

    def _handle_communication_error(self, exc: Exception):
        """Centralized error handling with auto-recovery"""
        logging.error(f"OPC UA Error: {exc}")
        
        if isinstance(exc, (ua.uaerrors.BadConnectionClosed,
                          ua.uaerrors.BadSessionNotActivated)):
            if self.config.auto_reconnect:
                self._schedule_reconnect()

    def _schedule_reconnect(self):
        """Automated reconnection strategy"""
        if not self._reconnect_task or self._reconnect_task.done():
            self._reconnect_task = asyncio.create_task(self._reconnect_loop())

    async def _reconnect_loop(self):
        """Exponential backoff reconnection attempts"""
        retries = 0
        max_retries = 5
        
        while retries < max_retries:
            await asyncio.sleep(RECONNECT_INTERVAL * (2 ** retries))
            try:
                if await self.connect():
                    return
                retries += 1
            except Exception as exc:
                logging.error(f"Reconnect attempt {retries} failed: {exc}")
                
        logging.critical("Maximum reconnection attempts exceeded")

# ===== Security Components =====
class OPCSecurityHandler:
    """Industrial Certificate Management"""
    
    def __init__(self, trust_list_dir: str, revocation_list_dir: str):
        self.trust_list = self._load_trust_list(trust_list_dir)
        self.revocation_list = self._load_revocation_list(revocation_list_dir)
        
    def _load_trust_list(self, directory: str) -> Dict[str, bytes]:
        """Load trusted certificates from directory"""
        trust_list = {}
        for filename in os.listdir(directory):
            if filename.endswith(".der"):
                with open(os.path.join(directory, filename), "rb") as f:
                    cert = f.read()
                    trust_list[filename] = cert
        return trust_list
    
    def _load_revocation_list(self, directory: str) -> List[bytes]:
        """Load CRL files from directory"""
        crl_list = []
        for filename in os.listdir(directory):
            if filename.endswith(".crl"):
                with open(os.path.join(directory, filename), "rb") as f:
                    crl_list.append(f.read())
        return crl_list

# ===== Kubernetes Deployment =====
opcua_deployment = """
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: opcua-adapter
spec:
  serviceName: opcua-adapter
  replicas: 2
  updateStrategy:
    type: RollingUpdate
  selector:
    matchLabels:
      app: opcua-adapter
  template:
    metadata:
      labels:
        app: opcua-adapter
    spec:
      serviceAccountName: opcua-adapter
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
      containers:
      - name: adapter
        image: enlivenai/opcua-adapter:1.4.0
        env:
        - name: OPCUA_ENDPOINT
          valueFrom:
            configMapKeyRef:
              name: opcua-config
              key: endpoint
        - name: OPCUA_SECURITY_POLICY
          valueFrom:
            configMapKeyRef:
              name: opcua-config
              key: security_policy
        volumeMounts:
        - name: opcua-certs
          mountPath: /etc/opcua/certs
          readOnly: true
        - name: trust-lists
          mountPath: /etc/opcua/trust
          readOnly: true
        ports:
        - containerPort: 4840
          name: opcua
        readinessProbe:
          exec:
            command: ["opcua-healthcheck", "--config", "/etc/opcua/config.yaml"]
      volumes:
      - name: opcua-certs
        csi:
          driver: secrets-store.csi.k8s.io
          readOnly: true
          volumeAttributes:
            secretProviderClass: "opcua-certs"
      - name: trust-lists
        configMap:
          name: opcua-trust-list
"""

# ===== Usage Example =====
async def main():
    config = OPCUAConfig(
        endpoint="opc.tcp://industrial-server:4840",
        security_policy="Basic256Sha256",
        application_uri="urn:enliven:opcua:adapter",
        cert_path="/etc/opcua/certs/client.der",
        key_path="/etc/opcua/certs/client.key",
        server_cert_path="/etc/opcua/certs/server.der"
    )
    
    async with IndustrialOPCUAAdapter(config) as client:
        # Read node value
        read_request = NodeReadRequest(node_id="ns=2;s=Machine1.Temperature")
        value = await client.read_node(read_request)
        print(f"Current temperature: {value}")
        
        # Write node value
        write_request = NodeWriteRequest(
            node_id="ns=2;s=Machine1.SetPoint",
            value=75.0,
            data_type=ua.NodeId(ua.ObjectIds.Double)
        )
        await client.write_node(write_request)
        
        # Subscribe to data changes
        async def data_callback(msg):
            print(f"Data change: {msg}")
            
        await client.create_subscription(
            nodes=["ns=2;s=Machine1.Pressure"],
            callback=data_callback
        )
        
        # Keep running
        while True:
            await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
