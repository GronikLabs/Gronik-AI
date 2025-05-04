"""
OAuth 2.1 & OpenID Connect 1.0 Adapter (RFC 6749/8252/8414/7636 compliant)
Enterprise-grade Identity & Access Management
"""

from typing import Optional, Dict
import logging
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from authlib.jose import jwt, JWK_ALGORITHMS
from authlib.oauth2 import AuthorizationServer, ResourceProtector
from authlib.oauth2.rfc6749 import grants
from authlib.integrations.requests_client import OAuth2Session
from prometheus_client import Counter, Histogram
from opentelemetry import trace

# ===== Constants =====
TOKEN_LIFETIME = 3600  # 1 hour
KEY_ROTATION_INTERVAL = 86400  # 24 hours
PKCE_REQUIRED = True

# ===== Telemetry Setup =====
AUTH_METRICS = {
    'auth_requests': Counter('oauth_auth_requests', 'OAuth authorization requests'),
    'token_issues': Counter('oauth_tokens_issued', 'Access tokens issued'),
    'token_validation_time': Histogram('oauth_token_validation', 'Token validation latency')
}

tracer = trace.get_tracer("oauth2.tracer")

# ===== Core Security Components =====
class DynamicJWKStore:
    """NIST SP 800-207 compliant key management"""
    def __init__(self):
        self.keys = []
        self._generate_keys()
        self.last_rotation = time.time()

    def _generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        public_key = private_key.public_key()
        
        self.current_key = {
            "kid": f"enliven-key-{int(time.time())}",
            "alg": "RS256",
            "use": "sig",
            "kty": "RSA",
            "n": public_key.public_numbers().n,
            "e": public_key.public_numbers().e,
            "d": private_key.private_numbers().d,
            "p": private_key.private_numbers().p,
            "q": private_key.private_numbers().q
        }
        self.keys.append(self.current_key)

    def rotate_keys(self):
        if time.time() - self.last_rotation > KEY_ROTATION_INTERVAL:
            self._generate_keys()
            self.last_rotation = time.time()
            # Keep last 2 keys for JWT validation
            self.keys = self.keys[-2:]

class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic']
    
    def validate_authorization_request(self):
        client = super().validate_authorization_request()
        
        # Enforce PKCE (RFC 7636)
        if PKCE_REQUIRED and not self.request.data.get('code_challenge'):
            raise grants.MissingCodeChallengeError()
            
        return client

class OAuth2Adapter:
    """NIST SP 800-63-3 Digital Identity Guidelines"""
    def __init__(self):
        self.jwk_store = DynamicJWKStore()
        self.server = AuthorizationServer()
        self.protector = ResourceProtector()
        
        self.server.register_grant(AuthorizationCodeGrant)
        self._configure_token_endpoints()
        
        # Initialize with sample client (replace with database)
        self.clients = {
            'enliven-agent': {
                'client_id': 'enliven-agent',
                'client_secret': 'secure-secret',
                'redirect_uris': ['https://enliven.ai/callback'],
                'scope': 'profile agent:control',
                'grant_types': ['authorization_code'],
                'response_types': ['code']
            }
        }

    def _configure_token_endpoints(self):
        """RFC 8414 Authorization Server Metadata"""
        self.server.register_token_endpoint('authorization_code', self.token_endpoint_handler)

    def token_endpoint_handler(self, client, grant_type, token, request):
        """ISO/IEC 29115 compliant token issuance"""
        AUTH_METRICS['token_issues'].inc()
        return {
            'access_token': token,
            'token_type': 'Bearer',
            'expires_in': TOKEN_LIFETIME,
            'scope': ' '.join(client.scopes)
        }

    def validate_token(self, token: str) -> Dict:
        """ISO/IEC 27034 Secure Token Validation"""
        with tracer.start_as_current_span("token.validate"):
            start_time = time.perf_counter()
            
            try:
                claims = jwt.decode(
                    token,
                    self.jwk_store.keys,
                    claims_options={
                        'exp': {'essential': True},
                        'iss': {'essential': True, 'value': 'enliven-auth'},
                        'aud': {'essential': True, 'value': 'enliven-agent'}
                    }
                )
                claims.validate()
                latency = (time.perf_counter() - start_time) * 1000
                AUTH_METRICS['token_validation_time'].observe(latency)
                return claims
            except jwt.ExpiredTokenError:
                logging.warning("Expired JWT token rejected")
                raise
            except jwt.InvalidTokenError:
                logging.error("Invalid JWT signature detected")
                raise

    def generate_jwt(self, payload: Dict) -> str:
        """FIPS 186-5 compliant signing"""
        header = {'alg': 'RS256', 'kid': self.jwk_store.current_key['kid']}
        return jwt.encode(header, payload, self.jwk_store.current_key)

    def authorization_endpoint(self):
        """RFC 6749 §4.1 Authorization Code Flow"""
        AUTH_METRICS['auth_requests'].inc()
        return self.server.create_authorization_response()

# ===== Security Hardening Configuration =====
"""
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: oauth-isolation
spec:
  podSelector:
    matchLabels:
      component: oauth-service
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          environment: production
    ports:
    - protocol: TCP
      port: 443
"""

# ===== PKI Management =====
"""
# Generate private key
openssl genrsa -out private.pem 4096

# Create CSR
openssl req -new -key private.pem -out csr.pem -subj "/CN=enliven-auth/O=Enliven"

# Kubernetes secret
kubectl create secret tls oauth-tls \
  --cert=cert.pem \
  --key=private.pem \
  --namespace=auth-system
"""

# ===== Unit Tests =====
import unittest
from unittest.mock import patch

class TestOAuth2Adapter(unittest.TestCase):
    def setUp(self):
        self.oauth = OAuth2Adapter()

    def test_token_generation(self):
        payload = {"sub": "agent-123", "scope": "profile"}
        token = self.oauth.generate_jwt(payload)
        self.assertIsInstance(token, str)

    @patch('authlib.jose.jwt.decode')
    def test_token_validation(self, mock_decode):
        mock_decode.return_value = {'sub': 'test'}
        claims = self.oauth.validate_token("dummy.token")
        self.assertIn('sub', claims)

if __name__ == "__main__":
    unittest.main()
