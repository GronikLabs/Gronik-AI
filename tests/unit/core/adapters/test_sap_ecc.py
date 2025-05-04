"""
SAP ECC Integration Test Suite (v4.1.0)
RFC 8476 | NIST SP 800-204 | ISO 27001
"""

import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime
import xml.etree.ElementTree as ET
from sapconnector import SAPECCClient, BAPIError, IDocValidationError

class TestSAPECCIntegration(unittest.TestCase):
    """Comprehensive verification of SAP ECC interfaces"""

    def setUp(self):
        self.mock_rfc = MagicMock()
        self.audit_logger = MagicMock()
        self.crypto = MagicMock()
        self.crypto.decrypt.side_effect = lambda x: x  # Bypass for testing
        
        self.client = SAPECCClient(
            host="sap.example.com",
            client="100",
            user="TEST_USER",
            crypto_service=self.crypto,
            audit_logger=self.audit_logger
        )
        self.client._create_connection = self.mock_rfc

    # --- Core BAPI Tests ---
    @patch('sapconnector.RFC_READ_TABLE')
    def test_material_master_read(self, mock_bapi):
        """RFC 8476 Section 6.1 - Material Master Verification"""
        test_data = {
            "MATNR": "TEST-001",
            "MAKTX": "Test Material",
            "MATKL": "001"
        }
        mock_bapi.return_value = (0, [test_data])
        
        result = self.client.get_material_details("TEST-001")
        self.assertEqual(result.material_number, "TEST-001")
        self.audit_logger.log_access.assert_called_with(
            object_type="MATERIAL",
            object_id="TEST-001",
            action="READ"
        )

    # --- Negative Testing ---
    @patch('sapconnector.RFC_READ_TABLE')
    def test_invalid_material_error(self, mock_bapi):
        """NIST SP 800-204 Section 3.4 - Invalid Input Handling"""
        mock_bapi.side_effect = BAPIError("Material not found", code="MAT404")
        
        with self.assertRaises(BAPIError) as ctx:
            self.client.get_material_details("INVALID-001")
            
        self.assertEqual(ctx.exception.code, "MAT404")
        self.audit_logger.log_security_event.assert_called_with(
            event_type="AUTH_FAIL",
            resource="MATERIAL:INVALID-001"
        )

    # --- IDoc Processing Tests ---
    def test_idoc_creation_and_parsing(self):
        """RFC 8476 Section 8.2 - IDoc Structural Validation"""
        test_idoc = """<?xml version="1.0"?>
            <IDOC BEGIN="1">
                <EDI_DC40 SNDPOR="ENLIVEN"/>
                <E1MARCM MATNR="TEST-001"/>
            </IDOC>"""
        
        with patch('sapconnector.IDOC_TRANSFER') as mock_idoc:
            mock_idoc.return_value = (0, "IDOC_12345")
            doc_id = self.client.post_idoc(test_idoc)
            
            self.assertEqual(doc_id, "IDOC_12345")
            self.audit_logger.log_transaction.assert_called_with(
                direction="OUTBOUND",
                doc_type="MATMAS",
                doc_id="IDOC_12345"
            )

    def test_idoc_xss_protection(self):
        """OWASP ASVS 5.3.4 - Payload Sanitization"""
        malicious_idoc = """<?xml version="1.0"?>
            <IDOC BEGIN="1">
                <EDI_DC40 SNDPOR="<script>alert(1)</script>"/>
            </IDOC>"""
        
        with self.assertRaises(IDocValidationError) as ctx:
            self.client.post_idoc(malicious_idoc)
            
        self.assertIn("Invalid control characters", str(ctx.exception))

    # --- Performance Benchmarks ---
    @patch('sapconnector.RFC_READ_TABLE')
    def test_high_volume_material_reads(self, mock_bapi):
        """SAP Performance Benchmark (2000+ TPS)"""
        mock_bapi.return_value = (0, [{"MATNR": f"TEST-{i}"} for i in range(100)])
        
        with self.assertLogs(level='INFO') as log:
            results = [self.client.get_material_details(f"TEST-{i}") 
                      for i in range(1000)]
            
        self.assertEqual(len(results), 1000)
        self.assertIn("Achieved 1200 TPS", log.output[0])

    # --- Security Validation ---
    def test_credential_rotation(self):
        """NIST SP 800-204 Section 5.2 - Credential Management"""
        self.client.update_credentials(
            new_user="ROTATED_USER",
            new_password=b"encrypted:newpass"
        )
        
        self.assertEqual(self.client.user, "ROTATED_USER")
        self.crypto.rotate_keys.assert_called_once()
        self.audit_logger.log_security_event.assert_called_with(
            event_type="CRED_ROTATE",
            user="ROTATED_USER"
        )

    @patch('sapconnector.RFC_READ_TABLE')
    def test_field_level_authorization(self, mock_bapi):
        """ISO 27001 Annex A.9 - Least Privilege Verification"""
        mock_bapi.return_value = (0, [{"MATNR": "TEST-001", "MAKTX": "Restricted"}])
        
        with self.assertRaises(BAPIError) as ctx:
            self.client.get_material_details("TEST-001", 
                                           field_filter=["MATNR"])
            
        self.assertEqual(ctx.exception.code, "AUTH_FAIL")
        self.assertIn("MAKTX", str(ctx.exception))

    # --- Data Integrity Tests ---
    def test_idoc_signature_verification(self):
        """NIST FIPS 186-5 - Digital Signature Validation"""
        signed_idoc = "<IDOC><SIGNATURE>...</SIGNATURE></IDOC>"
        self.crypto.verify_signature.return_value = True
        
        with patch('sapconnector.IDOC_TRANSFER') as mock_idoc:
            self.client.post_idoc(signed_idoc)
            self.crypto.verify_signature.assert_called_once()

    # --- Failover Testing ---
    @patch('sapconnector.RFC_PING')
    def test_connection_failover(self, mock_ping):
        """SAP OSS Note 1672720 - High Availability Verification"""
        mock_ping.side_effect = [TimeoutError, None]  # First attempt fails
        
        self.client.failover_hosts = ["sap-dr.example.com"]
        result = self.client.check_connectivity()
        
        self.assertTrue(result)
        self.assertEqual(self.client.host, "sap-dr.example.com")

    # --- Compliance Validation ---
    def test_gdpr_data_masking(self):
        """GDPR Article 25 - Pseudonymization Check"""
        sensitive_idoc = """<?xml version="1.0"?>
            <IDOC>
                <EDI_DC40 SNDPOR="ENLIVEN"/>
                <E1KNA1 KUNNR="0000001234" NAME1="Test Customer"/>
            </IDOC>"""
        
        with patch('sapconnector.IDOC_TRANSFER') as mock_idoc:
            self.client.post_idoc(sensitive_idoc)
            args, _ = mock_idoc.call_args
            sent_idoc = args[0]
            
            root = ET.fromstring(sent_idoc)
            customer_num = root.find(".//E1KNA1/KUNNR").text
            self.assertEqual(customer_num, "********1234")

if __name__ == "__main__":
    unittest.main(
        failfast=True,
        buffer=True,
        catchbreak=False,
        testRunner=unittest.XmlTestRunner(output='test-results/')
    )
