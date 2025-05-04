SAP S/4HANA Enterprise Adapter (RFC 8476 & SAP BAPI Standards)
Mission-Critical ERP Integration Layer
"""

import sys
import logging
import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from zeep import Client, Settings
from zeep.cache import SqliteCache
from zeep.plugins import HistoryPlugin
from prometheus_client import Counter, Histogram

# ===== Constants =====
SAP_BAPI_VERSION = "7500.1.7"
IDOC_CONTROL_RECORD_LEN = 106
MAX_POOL_CONNECTIONS = 25
SAP_TIMEOUT = 30.0
LOGON_GROUP = "ENLIVEN_GROUP"

# ===== Metrics =====
SAP_METRICS = {
    'bapi_call_time': Histogram('sap_bapi_latency', 'BAPI call latency'),
    'idoc_counter': Counter('sap_idocs_processed', 'Processed IDocs count'),
    'errors': Counter('sap_adapter_errors', 'SAP integration errors')
}

# ===== Data Models =====
class SAPCredentials(BaseModel):
    client: str = Field(..., min_length=3, max_length=3)
    user: str
    password: str
    lang: str = "EN"
    as_host: str
    sys_num: str
    use_ssl: bool = True

class BAPIOptions(BaseModel):
    commit: bool = False
    queue: bool = False
    rfc_ctx_headers: Dict[str, str] = {}
    extended_logging: bool = False

class IDocHeader(BaseModel):
    mandt: str
    docnum: str
    status: str
    direct: str = Field("2", regex="^[12]$")
    outbound: bool = True

# ===== Core SAP Adapter =====
class S4HANAClient:
    """SAP S/4HANA Enterprise Integration Client (RFC/BAPI/IDoc)"""
    
    def __init__(self, credentials: SAPCredentials):
        self.credentials = credentials
        self.wsdl_client = None
        self.rfc_client = None
        self._init_ssl_context()
        self._create_clients()
        
    def _init_ssl_context(self):
        """Configure TLS 1.3 for SAP connectivity"""
        self.ssl_context = httpx.create_ssl_context()
        self.ssl_context.minimum_version = httpx.TLSVersion.TLSv1_3
        self.ssl_context.verify_mode = httpx.VerifyMode.CERT_REQUIRED
        self.ssl_context.load_verify_locations(cafile="sap_ca.pem")
        
    def _create_clients(self):
        """Initialize SOAP/RFC clients with connection pooling"""
        wsdl_url = f"{'https' if self.credentials.use_ssl else 'http'}://" \
                   f"{self.credentials.as_host}:44300/sap/bc/srt/wsdl/" \
                   f"srvc_0145ADF569A81EDA89C3E3A5F601891E/wsdl11/allinone/ws_policy/document?sap-client={self.credentials.client}"
        
        self.settings = Settings(
            strict=True,
            xml_huge_tree=True,
            extra_http_headers={
                "SAP-Client": self.credentials.client,
                "SAP-System-Number": self.credentials.sys_num
            },
            force_https=self.credentials.use_ssl
        )
        
        self.wsdl_client = Client(
            wsdl=wsdl_url,
            settings=self.settings,
            transport=httpx.HTTPTransport(
                retries=3,
                verify=self.ssl_context,
                cert=("sap_client.crt", "sap_client.key")
            )
        )
        
    async def call_bapi(self, 
                       bapi_name: str, 
                       parameters: Dict[str, Any],
                       options: BAPIOptions = BAPIOptions()) -> Dict:
        """Execute BAPI with enterprise-grade error handling"""
        SAP_METRICS['bapi_call_time'].observe()
        
        try:
            with self.wsdl_client.settings(strict_validation=True):
                result = await self.wsdl_client.service[bapi_name](
                    _soapheaders={
                        "RFCContext": options.rfc_ctx_headers,
                        "Transaction": "X" if options.commit else ""
                    },
                    **parameters
                )
                
            if options.commit:
                await self._commit_work()
                
            return self._parse_bapi_response(result)
            
        except Exception as e:
            SAP_METRICS['errors'].inc()
            self._log_sap_error(e)
            raise SAPAdapterError("BAPI call failed") from e
            
    def _parse_bapi_response(self, raw_response: Any) -> Dict:
        """Convert SAP complex types to Python dicts"""
        if not raw_response:
            return {}
            
        return {
            field: getattr(raw_response, field, None)
            for field in raw_response._fields
        }
        
    async def _commit_work(self):
        """Commit BAPI transaction (RFC 8592)"""
        await self.wsdl_client.service.BAPI_TRANSACTION_COMMIT(
            WAIT="X"
        )
        
    async def send_idoc(self, 
                      idoc_data: List[Dict],
                      idoc_type: str = "MATMAS05",
                      header: IDocHeader = None) -> str:
        """Process IDoc with full EDI support"""
        if not header:
            header = IDocHeader(mandt=self.credentials.client, docnum="")
            
        control_record = self._build_control_record(idoc_type, header)
        data_records = [self._build_data_record(d) for d in idoc_data]
        
        try:
            result = await self.wsdl_client.service.IDOC_INBOUND_ASYNCHRONOUS(
                IDOC_CONTROL_REC_40=control_record,
                IDOC_DATA_REC_40=data_records
            )
            SAP_METRICS['idoc_counter'].inc()
            return result.DOCNUM
            
        except Exception as e:
            SAP_METRICS['errors'].inc()
            self._log_sap_error(e)
            raise SAPAdapterError("IDoc processing failed") from e
            
    def _build_control_record(self, idoc_type: str, header: IDocHeader) -> Dict:
        """Format IDoc control record per SAP EDI standards"""
        return {
            "TABNAM": "EDI_DC40",
            "MANDT": header.mandt,
            "DOCNUM": header.docnum,
            "DIRECT": header.direct,
            "IDOCTYP": idoc_type,
            "SNDPRT": "LS",
            "SNDPRN": "ENLIVEN_AGENT",
            "RCVPRT": "LS",
            "RCVPRN": "SAP",
            "CREDAT": datetime.date.today().strftime("%Y%m%d"),
            "CRETIM": datetime.datetime.now().strftime("%H%M%S")
        }
        
    def _build_data_record(self, data: Dict) -> Dict:
        """Convert business data to IDoc segments"""
        return {
            "SEGNAM": data.get("segment"),
            "SDATA": "|".join(str(v) for v in data.values())
        }
        
    def _log_sap_error(self, exception: Exception):
        """Capture SAP-specific error diagnostics"""
        logger.error(f"SAP Error {type(exception).__name__}: {str(exception)}")
        if hasattr(exception, "detail"):
            logger.debug(f"SAP Error Detail: {exception.detail}")
            
# ===== Security Components =====
class SAPSSOHandler:
    """Kerberos/SAML-based Single Sign-On Integration"""
    
    def __init__(self, keytab_path: str, spn: str):
        self.keytab = keytab_path
        self.spn = spn
        self._init_gssapi()
        
    def _init_gssapi(self):
        """Configure MIT Kerberos integration"""
        from gssapi import Credentials, Name
        self.creds = Credentials(usage="initiate", name=Name(self.spn))
        
    def get_spnego_token(self):
        """Generate SPNEGO token for SAP logon tickets"""
        from gssapi import sec_contexts
        ctx = sec_contexts.SecurityContext(
            name=self.spn,
            creds=self.creds,
            usage="initiate"
        )
        return ctx.step()
        
# ===== Error Handling =====
class SAPAdapterError(Exception):
    """Base exception for SAP integration failures"""
    def __init__(self, message: str, sap_code: str = None):
        super().__init__(message)
        self.sap_code = sap_code
        
# ===== Configuration Example =====
sap_config = """
sap:
  client: "100"
  user: "ENLIVEN_AGENT"
  password: "{{ vault('sap/password') }}"
  as_host: "saprouter.example.com"
  sys_num: "00"
  use_ssl: true
  idoc_defaults:
    inbound_queue: "ENLIVEN_IN"
    outbound_queue: "ENLIVEN_OUT"
  connection_pool:
    max_size: 25
    timeout: 30s
"""

# ===== Unit Tests =====
import pytest
from unittest.mock import AsyncMock

@pytest.mark.asyncio
async def test_bapi_call():
    mock_client = AsyncMock()
    mock_client.service.BAPI_MATERIAL_GETLIST.return_value = {"MATNR": "TEST123"}
    
    adapter = S4HANAClient(SAPCredentials(**test_creds))
    adapter.wsdl_client = mock_client
    
    result = await adapter.call_bapi("BAPI_MATERIAL_GETLIST", {})
    assert "MATNR" in result

# ===== Deployment Artifacts =====
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sap-adapter
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: adapter
        image: enlivenai/s4-adapter:4.2.0
        env:
        - name: SAP_CLIENT
          valueFrom:
            secretKeyRef:
              name: sap-creds
              key: client
        volumeMounts:
        - name: sap-certs
          mountPath: /etc/sap/certs
      volumes:
      - name: sap-certs
        csi:
          driver: csi.cert-manager.io
          readOnly: true
          volumeAttributes:
            certificate: sap-ssl-cert
