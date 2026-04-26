"""
Military-grade test suite for P-521 E2E Secure Communications
"""

import asyncio
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Import the main module using importlib to handle numeric filename
spec = importlib.util.spec_from_file_location("secure_coms", Path(__file__).parent / "0x1FC_p-521_E2E_SecureComs.py")
secure_coms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(secure_coms)


class TestOverlayCrypto(unittest.TestCase):
    """Test OverlayCrypto encryption/decryption with PFS"""
    
    def setUp(self):
        """Set up test fixtures"""
        Identity = secure_coms.Identity
        OverlayCrypto = secure_coms.OverlayCrypto
        
        # Create test identity
        private_key = ec.generate_private_key(ec.SECP521R1())
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Use the same fingerprint format as the secure_coms module
        fp = hashlib.sha256(public_der).hexdigest().upper()
        fp = ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))
        
        self.identity = Identity(
            private_key=private_key,
            public_pem=public_pem,
            public_der=public_der,
            fingerprint=fp,
            storage_key=b"test_storage_key",
            display_name="TestUser"
        )
        
        self.room_key = b"test_room_key_32_bytes_long_"
        self.overlay = OverlayCrypto(self.identity, self.room_key)
    
    def test_overlay_initialization(self):
        """Test OverlayCrypto initialization"""
        self.assertIsNotNone(self.overlay.room_key)
        self.assertIsNotNone(self.overlay.room_id)
        self.assertIsNotNone(self.overlay.nonce_prefix)
    
    def test_counter_increment(self):
        """Test message counter increment"""
        initial_counter = self.overlay.send_counter
        
        packet = {"kind": "message", "body": "Test"}
        self.overlay.encrypt_packet(packet)
        
        self.assertGreater(self.overlay.send_counter, initial_counter)
    
    def test_message_compression(self):
        """Test message compression"""
        test_data = b"test message " * 100  # Repeated data for compression
        compressed = self.overlay.compress_data(test_data)
        self.assertLess(len(compressed), len(test_data))
        
        decompressed = self.overlay.decompress_data(compressed)
        self.assertEqual(decompressed, test_data)
    
    def test_message_deduplication(self):
        """Test message deduplication"""
        msg_id = "test_msg_123"
        
        # First call should return False (not duplicate)
        self.assertFalse(self.overlay.is_duplicate_message(msg_id))
        
        # Second call should return True (duplicate)
        self.assertTrue(self.overlay.is_duplicate_message(msg_id))
    
    def test_encrypt_packet(self):
        """Test packet encryption"""
        packet = {
            "kind": "message",
            "body": "Test message"
        }
        
        envelope = self.overlay.encrypt_packet(packet)
        
        self.assertEqual(envelope["type"], "e2e")
        self.assertIn("ciphertext", envelope)
        self.assertIn("signature", envelope)
        self.assertIn("sender_public_pem", envelope)
        self.assertIn("nonce_prefix", envelope)
        self.assertIn("counter", envelope)
        self.assertIn("compressed", envelope)
    
    def test_decrypt_envelope(self):
        """Test envelope decryption with PFS"""
        packet = {
            "kind": "message",
            "body": "Test message"
        }
        
        envelope = self.overlay.encrypt_packet(packet)
        decrypted = self.overlay.decrypt_envelope(envelope)
        
        self.assertIsNotNone(decrypted)
        self.assertEqual(decrypted["kind"], "message")
        self.assertEqual(decrypted["body"], "Test message")
    
    def test_sealed_sender_mode(self):
        """Test sealed sender mode"""
        sealed_overlay = secure_coms.OverlayCrypto(self.identity, self.room_key, sealed_sender=True)
        
        packet = {"kind": "message", "body": "Sealed test"}
        envelope = sealed_overlay.encrypt_packet(packet)
        
        self.assertTrue(envelope["sealed"])
        self.assertIn("routing_tag", envelope)
        self.assertNotIn("sender_fp", envelope)


class TestRateLimiting(unittest.TestCase):
    """Test rate limiting and DDoS protection"""
    
    def setUp(self):
        """Set up test fixtures"""
        BlindRelayServer = secure_coms.BlindRelayServer
        self.relay = BlindRelayServer("test_token")
    
    def test_rate_limit_check(self):
        """Test rate limiting logic"""
        client_id = "test_client"
        
        # First 100 messages should pass
        for i in range(100):
            self.assertFalse(self.relay.is_rate_limited(client_id))
        
        # 101st message should be rate limited
        self.assertTrue(self.relay.is_rate_limited(client_id))
    
    def test_ban_expiry(self):
        """Test automatic ban expiry"""
        client_id = "test_client"
        
        # Force ban
        self.relay.banned_clients.add(client_id)
        self.relay.ban_expiry[client_id] = 0  # Expired
        
        # Should not be rate limited after expiry
        self.assertFalse(self.relay.is_rate_limited(client_id))
        self.assertNotIn(client_id, self.relay.banned_clients)


class TestDatabase(unittest.TestCase):
    """Test SQLite database operations"""
    
    def setUp(self):
        """Set up test fixtures"""
        import tempfile
        self.temp_dir = tempfile.mkdtemp()
        
        # Mock APP_DIR
        self.original_app_dir = secure_coms.APP_DIR
        secure_coms.APP_DIR = Path(self.temp_dir)
        
        secure_coms.initialize_database()
        
        # Database path after initialization
        self.db_path = secure_coms.APP_DIR / "messages.db"
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        secure_coms.APP_DIR = self.original_app_dir
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_database_initialization(self):
        """Test database initialization"""
        self.assertTrue(self.db_path.exists())
    
    def test_store_message(self):
        """Test message storage"""
        secure_coms.store_message(
            msg_id="test_msg_1",
            room_id="test_room",
            sender_fp="test_fp",
            sender_name="TestUser",
            kind="message",
            body="Test message",
            timestamp=1234567890
        )
        
        # Verify message was stored
        messages = secure_coms.get_messages("test_room")
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["msg_id"], "test_msg_1")
    
    def test_message_threading(self):
        """Test message threading"""
        # Store thread root
        secure_coms.store_message(
            msg_id="root_msg",
            room_id="test_room",
            sender_fp="test_fp",
            sender_name="TestUser",
            kind="message",
            body="Root message",
            timestamp=1234567890,
            thread_root_id="root_msg"
        )
        
        # Store reply
        secure_coms.store_message(
            msg_id="reply_msg",
            room_id="test_room",
            sender_fp="test_fp",
            sender_name="TestUser",
            kind="message",
            body="Reply",
            timestamp=1234567891,
            reply_to_msg_id="root_msg",
            thread_root_id="root_msg"
        )
        
        # Get thread
        thread = secure_coms.get_thread_messages("root_msg")
        self.assertEqual(len(thread), 2)
    
    def test_message_search(self):
        """Test message search"""
        secure_coms.store_message(
            msg_id="search_test",
            room_id="test_room",
            sender_fp="test_fp",
            sender_name="TestUser",
            kind="message",
            body="Searchable content here",
            timestamp=1234567890
        )
        
        results = secure_coms.search_messages("Searchable", "test_room")
        self.assertEqual(len(results), 1)
        self.assertIn("Searchable", results[0]["body"])


class TestAuditLogging(unittest.TestCase):
    """Test audit logging functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        import tempfile
        self.temp_dir = tempfile.mkdtemp()
        
        # Mock LOG_DIR
        self.original_log_dir = secure_coms.LOG_DIR
        secure_coms.LOG_DIR = Path(self.temp_dir)
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        secure_coms.LOG_DIR = self.original_log_dir
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_security_event_logging(self):
        """Test security event logging"""
        secure_coms.log_security_event("test_event", {"key": "value"})
        
        # Check log file was created
        log_file = Path(self.temp_dir) / "audit.log"
        self.assertTrue(log_file.exists())
        
        # Verify log content
        content = log_file.read_text()
        self.assertIn("test_event", content)
        self.assertIn("key", content)


class TestSignatureVerification(unittest.TestCase):
    """Test P-521 signature verification"""
    
    def test_signature_generation(self):
        """Test signature generation"""
        private_key = ec.generate_private_key(ec.SECP521R1())
        data = b"test data for signing"
        
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA512()))
        self.assertIsNotNone(signature)
        self.assertGreater(len(signature), 0)
    
    def test_signature_verification(self):
        """Test signature verification"""
        private_key = ec.generate_private_key(ec.SECP521R1())
        public_key = private_key.public_key()
        data = b"test data for signing"
        
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA512()))
        
        # Verify with correct key
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA512()))
        
        # Should fail with wrong data
        with self.assertRaises(Exception):
            public_key.verify(signature, b"wrong data", ec.ECDSA(hashes.SHA512()))


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestOverlayCrypto))
    suite.addTests(loader.loadTestsFromTestCase(TestRateLimiting))
    suite.addTests(loader.loadTestsFromTestCase(TestDatabase))
    suite.addTests(loader.loadTestsFromTestCase(TestAuditLogging))
    suite.addTests(loader.loadTestsFromTestCase(TestSignatureVerification))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
