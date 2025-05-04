"""
NetSuite Enterprise Client (2023.2 API)
NIST SP 800-204 & OAuth 2.1 Compliant Integration
"""

import sys
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, validator
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt
from prometheus_client import Counter, Histogram

# ===== Constants =====
NS_API_VERSION = "2023.2"
NS_OAUTH_SCOPE = "rest_webservices rest_query"
NS_TOKEN_URL = "https://{account}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token"
NS_BASE_URL = "https://{account}.suitetalk.api.netsuite.com/services/rest/"
QUERY_PAGE_SIZE = 1000
MAX_RETRIES = 3

# ===== Metrics =====
NS_METRICS = {
    'api_latency': Histogram('netsuite_api_latency', 'API call latency', ['operation']),
    'records_processed': Counter('netsuite_records', 'Processed records', ['entity']),
    'oauth_refreshes': Counter('netsuite_oauth_refreshes', 'Token refresh events')
}

# ===== Data Models =====
class NSOAuthConfig(BaseModel):
    client_id: str
    client_secret: str
    account_id: str
    private_key: str
    key_id: str
    token_ttl: int = Field(3600, ge=300)

class SuiteQLQuery(BaseModel):
    select: List[str]
    from_: str = Field(..., alias="from")
    where: Optional[str]
    orderBy: Optional[List[str]]
    limit: Optional[int] = Field(ge=1, le=10000)
    offset: Optional[int]

    @validator('select')
    def validate_select(cls, v):
        if not v:
            raise ValueError("SELECT clause cannot be empty")
        return v

class RecordOperation(BaseModel):
    record_type: str
    internal_id: Optional[str]
    body: Dict[str, Any]
    replace: bool = False

# ===== Core Client =====
class NetSuiteClient:
    """Enterprise NetSuite API Client with OAuth 2.0 JWT Bearer Flow"""
    
    def __init__(self, config: NSOAuthConfig):
        self.config = config
        self.session = httpx.AsyncClient(
            http2=True,
            timeout=30.0,
            limits=httpx.Limits(max_connections=25)
        )
        self.token = None
        self.token_expiry = None
        self._configure_tls()
        
    def _configure_tls(self):
        """Enforce TLS 1.3 with FIPS-compliant ciphers"""
        self.ssl_context = httpx.create_ssl_context()
        self.ssl_context.minimum_version = httpx.TLSVersion.TLSv1_3
        self.ssl_context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")
        
    async def _get_auth_token(self):
        """JWT Bearer Flow Implementation (RFC 7523)"""
        if self.token_valid:
            return
            
        assertion = self._create_jwt_assertion()
        
        response = await self.session.post(
            NS_TOKEN_URL.format(account=self.config.account_id),
            data={
                "grant_type": "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion,
                "scope": NS_OAUTH_SCOPE
            },
            auth=(self.config.client_id, self.config.client_secret)
        )
        
        response.raise_for_status()
        token_data = response.json()
        self.token = token_data["access_token"]
        self.token_expiry = datetime.now() + timedelta(seconds=token_data["expires_in"])
        NS_METRICS['oauth_refreshes'].inc()
        
    def _create_jwt_assertion(self) -> str:
        """Generate RSA-SHA256 Signed JWT Assertion"""
        private_key = serialization.load_pem_private_key(
            self.config.private_key.encode(),
            password=None
        )
        
        return jwt.encode(
            {
                "iss": self.config.client_id,
                "sub": self.config.client_id,
                "aud": NS_TOKEN_URL.format(account=self.config.account_id),
                "exp": datetime.utcnow() + timedelta(seconds=300),
                "jti": self._generate_jti()
            },
            private_key,
            algorithm="RS256",
            headers={"kid": self.config.key_id}
        )
        
    async def execute_query(self, query: SuiteQLQuery) -> List[Dict]:
        """Execute SuiteQL Query with Auto-Pagination"""
        await self._ensure_auth()
        results = []
        current_offset = 0
        
        with NS_METRICS['api_latency'].labels("query").time():
            while True:
                query.offset = current_offset
                response = await self._api_request(
                    "POST",
                    "query/v1/suiteql",
                    json=query.dict(by_alias=True)
                )
                
                batch = response.get("items", [])
                results.extend(batch)
                NS_METRICS['records_processed'].labels(query.from_).inc(len(batch))
                
                if len(batch) < QUERY_PAGE_SIZE:
                    break
                current_offset += QUERY_PAGE_SIZE
                
        return results
        
    async def record_operation(self, operation: RecordOperation) -> Dict:
        """Perform CRUD Operation on NetSuite Records"""
        await self._ensure_auth()
        method = "PUT" if operation.internal_id else "POST"
        endpoint = f"record/v1/{operation.record_type}"
        
        if operation.internal_id:
            endpoint += f"/{operation.internal_id}"
            if operation.replace:
                endpoint += "?replace=true"
                
        with NS_METRICS['api_latency'].labels("record_write").time():
            response = await self._api_request(
                method,
                endpoint,
                json=operation.body
            )
            
        return response
        
    async def _api_request(self, method: str, path: str, **kwargs) -> Dict:
        """Execute API Call with Retry Logic"""
        url = NS_BASE_URL.format(account=self.config.account_id) + path
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Prefer": "transient",
            "X-NetSuite-PropertyCase": "lowerCamelCase"
        }
        
        for attempt in range(MAX_RETRIES):
            try:
                response = await self.session.request(
                    method,
                    url,
                    headers=headers,
                    ssl=self.ssl_context,
                    **kwargs
                )
                
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 5))
                    await asyncio.sleep(retry_after)
                    continue
                    
                response.raise_for_status()
                return response.json()
                
            except httpx.HTTPStatusError as e:
                self._handle_api_error(e)
                
        raise NetSuiteError("API request failed after retries")
        
    def _handle_api_error(self, error: httpx.HTTPStatusError):
        """Parse NetSuite-specific error details"""
        error_body = error.response.json()
        logger.error(f"NetSuite API Error {error.response.status_code}: {error_body}")
        raise NetSuiteError(
            f"{error_body.get('title', 'Unknown error')} - {error_body.get('detail')}",
            code=error_body.get("status")
        )
        
    @property
    def token_valid(self) -> bool:
        return self.token and datetime.now() < self.token_expiry
        
    async def _ensure_auth(self):
        if not self.token_valid:
            await self._get_auth_token()
            
    def _generate_jti(self) -> str:
        """Generate JWT ID per RFC 7519"""
        return secrets.token_urlsafe(32)

# ===== Security Components =====
class NSKeyRotator:
    """Automated Key Rotation for OAuth Certificates"""
    
    def __init__(self, config: NSOAuthConfig):
        self.config = config
        self.key_pair = None
        
    def rotate_keys(self):
        """Generate New RSA Key Pair"""
        self.key_pair = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        
        new_private = self.key_pair.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        public = self.key_pair.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        return {"private_key": new_private, "public_key": public}

# ===== Error Handling =====
class NetSuiteError(Exception):
    def __init__(self, message: str, code: Optional[int] = None):
        super().__init__(message)
        self.code = code
        
# ===== Configuration Example =====
ns_config = """
netsuite:
  client_id: "envliven_agent"
  client_secret: "{{ vault('netsuite/secret') }}"
  account_id: "ACME_123"
  key_id: "v1|12345|4096"
  private_key: |
    -----BEGIN PRIVATE KEY-----
    ...
  token_ttl: 3000
"""

# ===== Unit Tests =====
import pytest
from unittest.mock import AsyncMock

@pytest.mark.asyncio
async def test_query_execution():
    mock_response = {"items": [{"id": "123"}]}
    mock_client = AsyncMock()
    mock_client.post.return_value.json.return_value = mock_response
    
    client = NetSuiteClient(NSOAuthConfig(**test_config))
    client.session = mock_client
    
    results = await client.execute_query(SuiteQLQuery(
        select=["id", "name"],
        from="Customer",
        limit=100
    ))
    
    assert len(results) == 1

# ===== Deployment Artifacts =====
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netsuite-adapter
spec:
  replicas: 3
  strategy:
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    spec:
      containers:
      - name: adapter
        image: enlivenai/netsuite-client:3.2.0
        envFrom:
        - secretRef:
            name: netsuite-creds
        volumeMounts:
        - name: tls-certs
          mountPath: /etc/netsuite/certs
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
      volumes:
      - name: tls-certs
        csi:
          driver: secrets-store.csi.k8s.io
          readOnly: true
          volumeAttributes:
            secretProviderClass: "netsuite-tls"
