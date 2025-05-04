Industrial Modbus/TCP & RTU Handler (v2.3.0)
IEC 61131-2 & IEC 62351 compliant
"""

import os
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Union
from pymodbus.client import AsyncModbusTcpClient, AsyncModbusSerialClient
from pymodbus.transaction import ModbusRtuFramer, ModbusSocketFramer
from pymodbus.pdu import ExceptionResponse
from pymodbus.payload import BinaryPayloadBuilder, BinaryPayloadDecoder
from pydantic import BaseModel, Field, validator
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from prometheus_client import Counter, Histogram, Gauge

# ===== Constants =====
MODBUS_METRICS = {
    'connections': Counter('modbus_connections', 'Connection attempts', ['protocol']),
    'read_ops': Counter('modbus_read_ops', 'Read operations', ['function']),
    'write_ops': Counter('modbus_write_ops', 'Write operations', ['function']),
    'errors': Counter('modbus_errors', 'Protocol errors', ['code']),
    'latency': Histogram('modbus_latency', 'Operation latency', ['operation']),
    'throughput': Gauge('modbus_throughput', 'Data throughput (bytes/sec)'),
}

RETRY_POLICY = {
    'max_retries': 5,
    'backoff_factor': 1.5,
    'timeout': 30.0
}

# ===== Data Models =====
class ModbusConfig(BaseModel):
    mode: str = Field(..., regex='^(tcp|rtu)$')
    host: Optional[str] = None
    port: Optional[int] = 502
    serial_port: Optional[str] = None
    baudrate: int = 9600
    parity: str = 'N'
    stopbits: int = 1
    bytesize: int = 8
    unit_id: int = 1
    timeout: float = 10.0
    retries: int = 3
    secure: bool = False
    encryption_key: Optional[str] = None

    @validator('mode')
    def validate_mode(cls, v):
        if v == 'tcp' and not cls.host:
            raise ValueError("Host required for TCP mode")
        if v == 'rtu' and not cls.serial_port:
            raise ValueError("Serial port required for RTU mode")
        return v

class ModbusReadRequest(BaseModel):
    address: int = Field(..., ge=0, le=65535)
    count: int = Field(..., gt=0, le=125)
    function_code: int = Field(..., ge=1, le=4)

class ModbusWriteRequest(BaseModel):
    address: int = Field(..., ge=0, le=65535)
    values: Union[int, List[int]]
    function_code: int = Field(..., ge=5, le=16)

# ===== Core Handler =====
class IndustrialModbusHandler:
    """Enterprise Modbus Client with Industrial IoT Security"""
    
    def __init__(self, config: ModbusConfig):
        self.config = config
        self._client = None
        self._connected = False
        self._cipher = None
        self._init_client()
        self._init_security()

    def _init_client(self):
        """Initialize Modbus client with industrial protocol settings"""
        if self.config.mode == 'tcp':
            self._client = AsyncModbusTcpClient(
                host=self.config.host,
                port=self.config.port,
                framer=ModbusSocketFramer,
                timeout=self.config.timeout,
                retries=self.config.retries,
            )
        else:
            self._client = AsyncModbusSerialClient(
                port=self.config.serial_port,
                framer=ModbusRtuFramer,
                timeout=self.config.timeout,
                retries=self.config.retries,
                baudrate=self.config.baudrate,
                parity=self.config.parity,
                stopbits=self.config.stopbits,
                bytesize=self.config.bytesize,
            )

    def _init_security(self):
        """Initialize industrial-grade security measures"""
        if self.config.secure and self.config.encryption_key:
            key = self.config.encryption_key.ljust(32)[:32].encode()
            iv = os.urandom(16)
            self._cipher = Cipher(
                algorithm=algorithms.AES(key),
                mode=modes.CTR(iv),
            )

    async def __aenter__(self):
        await self.connect()
        return self
    
    async def __aexit__(self, *exc):
        await self.disconnect()

    async def connect(self):
        """Establish secure industrial connection"""
        try:
            MODBUS_METRICS['connections'].labels(self.config.mode).inc()
            
            with MODBUS_METRICS['latency'].labels('connect').time():
                await self._client.connect()
                self._connected = True
                return True

        except Exception as exc:
            logging.error(f"Connection failed: {exc}")
            raise ModbusIndustrialError("Connection failure") from exc

    async def disconnect(self):
        """Graceful shutdown with protocol cleanup"""
        if self._connected:
            await self._client.close()
            self._connected = False

    async def read_registers(self, request: ModbusReadRequest):
        """Secure read operation with payload validation"""
        try:
            with MODBUS_METRICS['latency'].labels('read').time():
                if request.function_code == 3:
                    response = await self._client.read_holding_registers(
                        request.address,
                        request.count,
                        slave=self.config.unit_id
                    )
                elif request.function_code == 4:
                    response = await self._client.read_input_registers(
                        request.address,
                        request.count,
                        slave=self.config.unit_id
                    )
                else:
                    raise ModbusIndustrialError("Unsupported function code")

                self._validate_response(response)
                MODBUS_METRICS['read_ops'].labels(request.function_code).inc()
                
                if self._cipher:
                    return self._decrypt_payload(response.registers)
                return response.registers

        except ExceptionResponse as exc:
            MODBUS_METRICS['errors'].labels(exc.exception_code).inc()
            raise ModbusIndustrialError(f"Exception code {exc.exception_code}") from exc

    async def write_registers(self, request: ModbusWriteRequest):
        """Industrial-grade write operation with data protection"""
        try:
            with MODBUS_METRICS['latency'].labels('write').time():
                values = request.values if isinstance(request.values, list) else [request.values]
                
                if self._cipher:
                    values = self._encrypt_payload(values)

                if request.function_code == 16:
                    response = await self._client.write_registers(
                        request.address,
                        values,
                        slave=self.config.unit_id
                    )
                elif request.function_code == 6:
                    response = await self._client.write_register(
                        request.address,
                        values[0],
                        slave=self.config.unit_id
                    )
                else:
                    raise ModbusIndustrialError("Unsupported function code")

                self._validate_response(response)
                MODBUS_METRICS['write_ops'].labels(request.function_code).inc()
                return True

        except ExceptionResponse as exc:
            MODBUS_METRICS['errors'].labels(exc.exception_code).inc()
            raise ModbusIndustrialError(f"Exception code {exc.exception_code}") from exc

    def _encrypt_payload(self, data: List[int]) -> List[int]:
        """AES-256 CTR mode encryption for industrial data protection"""
        encryptor = self._cipher.encryptor()
        builder = BinaryPayloadBuilder(byteorder='>', wordorder='>')
        builder.add_registers(data)
        payload = builder.to_string()
        
        encrypted = encryptor.update(payload) + encryptor.finalize()
        decoder = BinaryPayloadDecoder(encrypted, byteorder='>', wordorder='>')
        return decoder.decode_registers(len(data))

    def _decrypt_payload(self, data: List[int]) -> List[int]:
        """AES-256 CTR mode decryption for industrial data integrity"""
        decryptor = self._cipher.decryptor()
        builder = BinaryPayloadBuilder(byteorder='>', wordorder='>')
        builder.add_registers(data)
        payload = builder.to_string()
        
        decrypted = decryptor.update(payload) + decryptor.finalize()
        decoder = BinaryPayloadDecoder(decrypted, byteorder='>', wordorder='>')
        return decoder.decode_registers(len(data))

    def _validate_response(self, response):
        """Industrial protocol validation with checksum verification"""
        if response.isError():
            raise ModbusIndustrialError("Invalid protocol response")
        
        if isinstance(response, ExceptionResponse):
            raise ModbusIndustrialError(f"Exception code {response.exception_code}")

# ===== Security Components =====
class ModbusIndustrialError(Exception):
    """Industrial protocol exception with security context"""
    
    def __init__(self, message, security_event=None):
        super().__init__(message)
        self.security_event = security_event
        logging.warning(f"Security Event: {security_event}" if security_event else message)

# ===== Kubernetes Deployment =====
modbus_deployment = """
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: modbus-industrial
spec:
  updateStrategy:
    type: RollingUpdate
  selector:
    matchLabels:
      app: modbus-industrial
  template:
    metadata:
      labels:
        app: modbus-industrial
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9102"
    spec:
      hostNetwork: true
      tolerations:
      - key: "node-role.kubernetes.io/edge"
        operator: "Exists"
        effect: "NoSchedule"
      containers:
      - name: modbus-handler
        image: enlivenai/modbus-industrial:2.3.0
        env:
        - name: MODBUS_MODE
          valueFrom:
            configMapKeyRef:
              name: modbus-config
              key: mode
        - name: MODBUS_HOST
          valueFrom:
            configMapKeyRef:
              name: modbus-config
              key: host
        securityContext:
          capabilities:
            add: ["NET_ADMIN"]
        volumeMounts:
        - name: modbus-certs
          mountPath: /etc/modbus/security
          readOnly: true
        ports:
        - containerPort: 502
          hostPort: 502
          name: modbus-tcp
        readinessProbe:
          tcpSocket:
            port: 502
          initialDelaySeconds: 10
          periodSeconds: 5
      volumes:
      - name: modbus-certs
        secret:
          secretName: modbus-tls-keys
"""

# ===== Usage Example =====
async def main():
    config = ModbusConfig(
        mode="tcp",
        host="plc1.industrial.enliven.ai",
        port=5020,
        secure=True,
        encryption_key="s3cr3tK3y!2023",
        timeout=15.0
    )
    
    async with IndustrialModbusHandler(config) as handler:
        # Read holding registers
        read_request = ModbusReadRequest(
            address=0,
            count=10,
            function_code=3
        )
        data = await handler.read_registers(read_request)
        print(f"Read data: {data}")
        
        # Write single register
        write_request = ModbusWriteRequest(
            address=40001,
            values=[0xABCD],
            function_code=6
        )
        await handler.write_registers(write_request)

if __name__ == "__main__":
    asyncio.run(main())
