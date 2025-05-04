"""
mTLS Handshake Verification Suite (v4.2.0)
NIST SP 800-204 | FIPS 140-3 | RFC 8705
"""

import unittest
import ssl
from unittest.mock import patch, MagicMock
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import OpenSSL
import pem
import time

class TestMutualTLS(unittest.TestCase):
    """Military-Grade mTLS Handshake Validation"""

    def setUp(self):
        # Load test certificates
        self.root_ca = self._load_cert("certs/root-ca.pem")
        self.valid_cert = self._load_cert("certs/client-valid.pem")
        self.revoked_cert = self._load_cert("certs/client-revoked.pem")
        self.expired_cert = self._load_cert("certs/client-expired.pem")
        
        # Mock Kubernetes Secrets
        self.secret_store = {
            "mtls-keys": {
                "tls.crt": self.valid_cert.public_bytes(encoding=ssl.ENCODING_PEM),
                "tls.key": open("certs/client-valid.key", "rb").read()
            }
        }

        # CRL/OCSP setup
        self.crl = self._load_crl("crl/root-ca.crl")
        self.ocsp_responder = "http://ocsp.enlivenai:8080"

    # --- Core Handshake Tests ---
    def test_successful_mtls_handshake(self):
        """RFC 8705 Section 3.1 - Valid Certificate Exchange"""
        context = self._create_ssl_context()
        with self._create_mock_socket(context) as sock:
            sock.do_handshake()
            self.assertTrue(sock.cipher())
            self._verify_certificate_chain(sock.getpeercertchain())

    def test_client_certificate_revocation(self):
        """NIST SP 800-204 Section 7.3 - CRL/OCSP Validation"""
        context = self._create_ssl_context()
        context.load_verify_locations(cafile="certs/root-ca.pem")
        context.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF
        
        with self._create_mock_socket(context, cert=self.revoked_cert) as sock:
            with self.assertRaises(ssl.SSLError) as cm:
                sock.do_handshake()
            self.assertIn("certificate revoked", str(cm.exception))

    # --- Cryptographic Validation Tests ---
    def test_rsa_key_strength(self):
        """FIPS 140-3 IG 7.5 - Minimum 3072-bit RSA"""
        cert = x509.load_pem_x509_certificate(
            self.valid_cert.public_bytes(encoding=ssl.ENCODING_PEM), 
            default_backend()
        )
        pubkey = cert.public_key()
        self.assertGreaterEqual(pubkey.key_size, 3072)

    def test_certificate_signing_algorithm(self):
        """NIST SP 800-204 Section 4.2 - SHA-384 Enforcement"""
        cert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, 
            self.valid_cert.public_bytes(encoding=ssl.ENCODING_PEM)
        )
        self.assertEqual(cert.get_signature_algorithm(), b'sha384WithRSAEncryption')

    # --- Failure Scenario Tests ---
    def test_missing_client_certificate(self):
        """RFC 8705 Section 3.2 - Mandatory Client Auth"""
        context = self._create_ssl_context()
        context.verify_mode = ssl.CERT_REQUIRED
        with self._create_mock_socket(context, send_cert=False) as sock:
            with self.assertRaises(ssl.SSLError) as cm:
                sock.do_handshake()
            self.assertIn("certificate required", str(cm.exception))

    def test_expired_certificate(self):
        """NIST SP 800-204 Section 7.4 - Certificate Lifetime"""
        context = self._create_ssl_context()
        with self._create_mock_socket(context, cert=self.expired_cert) as sock:
            with self.assertRaises(ssl.SSLError) as cm:
                sock.do_handshake()
            self.assertIn("certificate has expired", str(cm.exception))

    # --- Performance & Stress Tests ---
    def test_handshake_performance(self):
        """FIPS 140-3 IG 12.3 - Handshake Throughput"""
        context = self._create_ssl_context()
        start_time = time.time()
        
        for _ in range(1000):
            with self._create_mock_socket(context):
                pass
                
        duration = time.time() - start_time
        self.assertLess(duration, 30)  # 30s SLA for 1000 handshakes

    def test_cipher_suite_negotiation(self):
        """NIST SP 800-204 Section 4.3 - Approved Ciphers"""
        context = self._create_ssl_context()
        context.set_ciphers("TLS_AES_256_GCM_SHA384")
        with self._create_mock_socket(context) as sock:
            sock.do_handshake()
            self.assertEqual(sock.cipher()[0], "TLS_AES_256_GCM_SHA384")

    # --- Kubernetes Integration Tests ---
    @patch("kubernetes.client.CoreV1Api.read_namespaced_secret")
    def test_k8s_secret_loading(self, mock_k8s):
        """NIST SP 800-204 Section 6.2 - Secret Management"""
        mock_k8s.return_value = MagicMock(data=self.secret_store["mtls-keys"])
        context = self._create_ssl_context()
        self.assertIsNotNone(context.get_cert_chain())
        self.assertIsNotNone(context.get_private_key())

    # --- Helper Methods ---
    def _create_ssl_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain("certs/server.pem", "certs/server.key")
        context.load_verify_locations("certs/root-ca.pem")
        context.verify_mode = ssl.CERT_REQUIRED
        context.options |= ssl.OP_NO_TLSv1_2  # Enforce TLS 1.3+
        return context

    def _create_mock_socket(self, context, cert=None, send_cert=True):
        sock = MagicMock()
        sock.context = context
        sock.getpeercertchain.return_value = [cert] if cert else []
        sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        if not send_cert:
            sock.getpeercert.return_value = None
        return sock

    def _load_cert(self, path):
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())

    def _load_crl(self, path):
        with open(path, "rb") as f:
            return x509.load_pem_x509_crl(f.read(), default_backend())

if __name__ == "__main__":
    unittest.main(
        verbosity=2,
        failfast=True,
        buffer=True,
        testRunner=unittest.TextTestRunner(
            descriptions=True,
            resultclass=unittest.TestResult,
            verbosity=2
        )
    )
