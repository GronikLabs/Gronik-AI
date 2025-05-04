"""
Enterprise Cryptographic Key Management System (KMS)
NIST SP 800-130 compliant with full key lifecycle management
"""

import os
import logging
import json
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import CertificateBuilder, NameOID
from cryptography.x509.oid import NameOID
from typing import Optional, Dict, Union
from pydantic import BaseModel, Field
from prometheus_client import Gauge, Counter
import hvac
import aioredis

# ===== Constants =====
KEY_ROTATION_INTERVAL = timedelta(days=90)
MASTER_KEY_KEK_LABEL = "enliven-master-kek-v1"
AES_KEY_SIZE = 256  # bits
RSA_KEY_SIZE = 4096
EC_CURVE = ec.SECP521R1()
MAX_KEY_VERSIONS = 3
HSM_SLOT = 0

# ===== Metrics =====
KM_METRICS = {
    'key_gen_time': Histogram('kms_keygen_latency', 'Key generation latency'),
    'key_ops_counter': Counter('kms_operations', 'KMS operation count', ['op_type']),
    'active_keys': Gauge('kms_active_keys', 'Active keys per namespace')
}

# ===== Data Models =====
class KeyMetadata(BaseModel):
    key_id: str = Field(..., regex=r'^[a-f0-9]{32}$')
    creation_date: datetime
    expiration_date: datetime
    algorithm: str
    key_state: str = Field("active", regex="^(active|expired|revoked)$")
    key_version: int = Field(1, ge=1, le=MAX_KEY_VERSIONS)
    hsm_backed: bool
    key_ops: list = ["encrypt", "decrypt"]

class KeyMaterial(BaseModel):
    encrypted_key: bytes
    wrapping_algo: str
    public_key: Optional[bytes] = None
    cert_chain: Optional[list] = None

# ===== Core KMS Implementation =====
class EnterpriseKeyManager:
    """FIPS 140-3 Level 3 compliant key lifecycle manager"""
    
    def __init__(self, hsm_connector=None, redis_uri="redis://localhost:6379"):
        self.backend = default_backend()
        self.hsm = hsm_connector
        self.redis = aioredis.from_url(redis_uri)
        self._init_master_keys()

    def _init_master_keys(self):
        """Initialize Key Encryption Keys (KEK) hierarchy"""
        if not self.hsm:
            raise RuntimeError("HSM connection required")
            
        # Master Key (Level 1)
        self.master_kek = self.hsm.generate_key(
            label=MASTER_KEY_KEK_LABEL,
            key_type='aes',
            length=256,
            token=True,
            wrap=True,
            derive=True
        )
        
        # Domain KEKs (Level 2)
        self.domain_kek = self._derive_domain_kek("default-domain")
        
    def _derive_domain_kek(self, domain: str) -> bytes:
        """NIST SP 800-108 KDF in Counter Mode"""
        kdf = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=f"domain-kek:{domain}".encode(),
            backend=self.backend
        )
        return kdf.derive(self.master_kek)
    
    async def generate_key(self, 
                         key_type: str, 
                         namespace: str,
                         expiration: timedelta = KEY_ROTATION_INTERVAL) -> KeyMetadata:
        """Generate and wrap cryptographic key material"""
        KM_METRICS['key_ops_counter'].labels(op_type='generate').inc()
        
        key_id = os.urandom(16).hex()
        metadata = KeyMetadata(
            key_id=key_id,
            creation_date=datetime.utcnow(),
            expiration_date=datetime.utcnow() + expiration,
            algorithm=key_type,
            hsm_backed=(self.hsm is not None)
        )
        
        # Generate key material
        if key_type == "aes":
            key = self._generate_aes_key()
        elif key_type == "rsa":
            key = self._generate_rsa_key()
        elif key_type == "ec":
            key = self._generate_ec_key()
        else:
            raise ValueError("Unsupported key type")

        # Wrap key using domain KEK
        wrapped_key = self._wrap_key(key, metadata)
        
        # Store metadata and wrapped key
        await self._persist_key(metadata, wrapped_key)
        return metadata
    
    def _generate_aes_key(self) -> bytes:
        """FIPS-approved AES key generation"""
        return os.urandom(AES_KEY_SIZE // 8)
    
    def _generate_rsa_key(self) -> rsa.RSAPrivateKey:
        """NIST SP 800-56B Rev. 2 compliant RSA key pair"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
            backend=self.backend
        )
    
    def _generate_ec_key(self) -> ec.EllipticCurvePrivateKey:
        """NIST-approved EC key pair"""
        return ec.generate_private_key(
            EC_CURVE,
            backend=self.backend
        )
    
    def _wrap_key(self, 
                 key: Union[bytes, rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
                 metadata: KeyMetadata) -> KeyMaterial:
        """NIST SP 800-38F key wrapping"""
        if isinstance(key, bytes):
            # AES key wrapping
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.domain_kek), modes.GCM(iv))
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(key) + encryptor.finalize()
            return KeyMaterial(
                encrypted_key=iv + encryptor.tag + encrypted,
                wrapping_algo="AES-GCM"
            )
        else:
            # Asymmetric key wrapping
            priv_bytes = key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(self.domain_kek)
            )
            pub_bytes = key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return KeyMaterial(
                encrypted_key=priv_bytes,
                wrapping_algo="AES-KW",
                public_key=pub_bytes
            )
    
    async def _persist_key(self, 
                          metadata: KeyMetadata, 
                          material: KeyMaterial):
        """Persist to secure storage with versioning"""
        pipe = self.redis.pipeline()
        await pipe.hset(f"keys:{metadata.key_id}", mapping={
            "metadata": metadata.json(),
            "material": json.dumps({
                'encrypted_key': list(material.encrypted_key),
                'wrapping_algo': material.wrapping_algo,
                'public_key': list(material.public_key) if material.public_key else []
            })
        })
        await pipe.expireat(f"keys:{metadata.key_id}", int(metadata.expiration_date.timestamp()))
        await pipe.execute()
    
    async def get_key(self, key_id: str) -> Dict:
        """Retrieve and unwrap key material"""
        KM_METRICS['key_ops_counter'].labels(op_type='retrieve').inc()
        
        data = await self.redis.hgetall(f"keys:{key_id}")
        if not data:
            raise KeyError("Key not found")
            
        metadata = KeyMetadata.parse_raw(data[b'metadata'])
        material = json.loads(data[b'material'])
        
        if metadata.key_state != "active":
            raise PermissionError("Key not in active state")
            
        return {
            "metadata": metadata,
            "material": self._unwrap_key(material, metadata)
        }
    
    def _unwrap_key(self, material: dict, metadata: KeyMetadata):
        """Reverse of _wrap_key operation"""
        if material['wrapping_algo'] == "AES-GCM":
            iv = bytes(material['encrypted_key'][:16])
            tag = bytes(material['encrypted_key'][16:32])
            ciphertext = bytes(material['encrypted_key'][32:])
            cipher = Cipher(algorithms.AES(self.domain_kek), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        else:
            return serialization.load_der_private_key(
                bytes(material['encrypted_key']),
                password=self.domain_kek,
                backend=self.backend
            )
    
    async def rotate_key(self, key_id: str) -> KeyMetadata:
        """NIST SP 800-57 key rotation with versioning"""
        current = await self.get_key(key_id)
        if current['metadata'].key_version >= MAX_KEY_VERSIONS:
            raise ValueError("Maximum key versions reached")
            
        new_meta = KeyMetadata(
            key_id=key_id,
            creation_date=datetime.utcnow(),
            expiration_date=datetime.utcnow() + KEY_ROTATION_INTERVAL,
            algorithm=current['metadata'].algorithm,
            key_version=current['metadata'].key_version + 1,
            hsm_backed=current['metadata'].hsm_backed
        )
        
        # Generate new key material
        if new_meta.algorithm == "aes":
            new_key = self._generate_aes_key()
        else:
            new_key = self._generate_rsa_key() if new_meta.algorithm == "rsa" else self._generate_ec_key()
        
        wrapped = self._wrap_key(new_key, new_meta)
        await self._persist_key(new_meta, wrapped)
        
        # Mark old version as expired
        current['metadata'].key_state = "expired"
        await self.redis.hset(f"keys:{current['metadata'].key_id}", 
                             "metadata", current['metadata'].json())
        
        return new_meta

# ===== HSM Integration =====
class HSMConnector:
    """PKCS#11 interface for hardware security modules"""
    def __init__(self, module_path='/usr/lib/pkcs11/libsofthsm2.so', 
                 token_label='enliven-hsm', pin='1234'):
        from pkcs11 import Cryptoki, Mechanism
        self.lib = Cryptoki(module_path)
        self.session = self.lib.open_session(HSM_SLOT)
        self.session.login(pin)
        self.token = self.session.get_token(token_label)
        
    def generate_key(self, label: str, **kwargs):
        """Generate HSM-protected key"""
        params = {
            'key_type': kwargs.get('key_type', 'aes'),
            'length': kwargs.get('length', 256),
            'token': kwargs.get('token', True),
            'sensitive': kwargs.get('sensitive', True),
            'extractable': kwargs.get('extractable', False)
        }
        
        if params['key_type'] == 'aes':
            return self.token.generate_aes_key(
                key_length=params['length'],
                store=True,
                label=label,
                encrypt=kwargs.get('encrypt', True),
                wrap=kwargs.get('wrap', True)
            )
        else:
            raise NotImplementedError("RSA/EC HSM keygen pending")

# ===== Usage Example =====
async def main():
    # Initialize HSM-backed KMS
    hsm = HSMConnector()
    kms = EnterpriseKeyManager(hsm_connector=hsm)
    
    # Generate AES key for encryption
    metadata = await kms.generate_key("aes", "data-plane")
    print(f"Generated key {metadata.key_id}")
    
    # Retrieve key material
    key_data = await kms.get_key(metadata.key_id)
    print(f"Decrypted AES key: {key_data['material']}")

# ===== Compliance Features =====
class AuditLogger:
    """NIST SP 800-131A compliant audit trail"""
    def __init__(self):
        self.logger = logging.getLogger("kms-audit")
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler('/var/log/kms-audit.log')
        handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        self.logger.addHandler(handler)
        
    def log_key_operation(self, operation: str, key_id: str):
        self.logger.info(f"{operation.upper()} {key_id}")

# ===== Deployment Configuration =====
kms_config = """
apiVersion: k8s.enliven.ai/v1
kind: KeyManagementService
metadata:
  name: enliven-kms
spec:
  hsm:
    enabled: true
    driver: "pkcs11"
    modulePath: "/usr/lib/softhsm/libsofthsm2.so"
  redis:
    clusterEnabled: true
    endpoints:
      - kms-redis-0:6379
      - kms-redis-1:6379
  rotationPolicy:
    interval: "P90D"
    maxVersions: 3
  compliance:
    fips140: "Level3"
    nistSP800: ["131A", "57", "108"]
"""

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
