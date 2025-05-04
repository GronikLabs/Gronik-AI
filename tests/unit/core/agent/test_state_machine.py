"""
State Machine Verification Suite (v3.1.0)
NIST SP 800-204 | ISO 55001 | Temporal Logic Validation
"""

import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime
import concurrent.futures
import hashlib

from core.agent.lifecycle.state_machine import AgentStateMachine
from exceptions import TransitionError, SecurityViolationError
from models.state import StateLogEntry

class TestAgentStateMachine(unittest.TestCase):
    """Comprehensive state transition verification"""

    def setUp(self):
        self.audit_logger = MagicMock()
        self.crypto_module = MagicMock()
        self.crypto_module.generate_state_hash.return_value = "0x1a3f..."
        
        self.sm = AgentStateMachine(
            initial_state="INIT",
            audit_logger=self.audit_logger,
            crypto=self.crypto_module
        )

    # --- Core Transition Tests ---
    def test_initial_state(self):
        """RFC 7271 Section 4.1 Initial State Verification"""
        self.assertEqual(self.sm.current_state, "INIT")
        self.assertEqual(self.sm.previous_state, None)
        self.assertEqual(self.sm.transition_count, 0)

    def test_valid_transition_sequence(self):
        """ISO 55001 Section 7.2 Valid Transition Path"""
        test_sequence = [
            ("INIT", "CONFIGURING", "system_init"),
            ("CONFIGURING", "READY", "config_complete"),
            ("READY", "PROCESSING", "task_received"),
            ("PROCESSING", "READY", "task_completed"),
            ("READY", "TERMINATING", "shutdown_signal"),
            ("TERMINATING", "TERMINATED", "cleanup_done")
        ]

        for from_state, to_state, event in test_sequence:
            with self.subTest(f"{from_state}→{to_state} via {event}"):
                self.sm._current_state = from_state
                self.sm.transition(event)
                self.assertEqual(self.sm.current_state, to_state)
                self.assertEqual(self.sm.previous_state, from_state)

    # --- Negative Transition Tests ---    
    def test_invalid_transition(self):
        """NIST SP 800-204 Section 3.4 Invalid Transition Handling"""
        with self.assertRaises(TransitionError) as ctx:
            self.sm.transition("invalid_event")
            
        self.assertEqual(ctx.exception.error_code, "FSM-001")
        self.assertIn("from INIT with event", str(ctx.exception))

    def test_duplicate_transition_attempt(self):
        """State Stability Verification (No-op Transition)"""
        self.sm.transition("system_init")
        initial_count = self.sm.transition_count
        
        with self.assertLogs(level="WARNING") as log:
            self.sm.transition("system_init")
            
        self.assertIn("Duplicate transition attempt", log.output[0])
        self.assertEqual(self.sm.transition_count, initial_count)

    # --- Security Verification ---
    def test_state_tampering_detection(self):
        """NIST SP 800-204 Section 5.3 Integrity Protection"""
        self.sm.transition("system_init")
        original_hash = self.sm.current_state_hash
        
        # Simulate memory tampering
        self.sm._current_state = "COMPROMISED"
        
        with self.assertRaises(SecurityViolationError) as ctx:
            self.sm.verify_state_integrity()
            
        self.assertEqual(ctx.exception.error_code, "SEC-409")

    def test_audit_log_verification(self):
        """ISO 27001 Annex A.12.4 Logging Requirements"""
        test_events = ["system_init", "config_complete", "task_received"]
        
        for event in test_events:
            self.sm.transition(event)
            
        logs = self.audit_logger.log_transition.call_args_list
        self.assertEqual(len(logs), len(test_events))
        
        for log, event in zip(logs, test_events):
            args = log[0][0]
            self.assertIsInstance(args, StateLogEntry)
            self.assertEqual(args.event, event)
            self.assertIsInstance(args.timestamp, datetime)

    # --- Concurrency Tests ---
    def test_thread_safety(self):
        """CIS Benchmark 5.2.7 Concurrency Validation"""
        self.sm._current_state = "READY"
        event_sequence = ["task_received"] * 100
        
        def transition_task():
            self.sm.transition("task_received")
            return self.sm.current_state

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(transition_task, event_sequence))
            
        valid_states = ["PROCESSING", "READY"]  # Allow final state
        self.assertTrue(all(s in valid_states for s in results))
        self.assertEqual(self.sm.transition_count, 100)

    # --- Failure Recovery Tests ---
    @patch('core.agent.lifecycle.state_machine.StatePersister')
    def test_persistence_recovery(self, mock_persister):
        """ISO 55001 Section 8.3 State Continuity Verification"""
        mock_persister.return_value.load.return_value = {
            'current_state': 'READY',
            'previous_state': 'CONFIGURING',
            'transition_count': 5,
            'hash_chain': ['0x1a3f...', '0x8b2c...']
        }
        
        recovered_sm = AgentStateMachine(
            initial_state="INIT",
            audit_logger=self.audit_logger,
            crypto=self.crypto_module
        )
        recovered_sm.restore_state()
        
        self.assertEqual(recovered_sm.current_state, "READY")
        self.assertEqual(recovered_sm.transition_count, 5)

    def test_rollback_mechanism(self):
        """NIST SP 800-204 Section 3.5 Transaction Rollback"""
        self.sm.transition("system_init")
        original_state = self.sm.current_state
        
        try:
            with self.sm.transaction():
                self.sm.transition("invalid_event")
        except TransitionError:
            pass
            
        self.assertEqual(self.sm.current_state, original_state)
        self.assertEqual(self.sm.transition_count, 1)  # Initial transition

    # --- Cryptographic Validation ---
    def test_state_hash_chain(self):
        """FIPS 140-3 Cryptographic Validation"""
        initial_hash = self.sm.current_state_hash
        events = ["system_init", "config_complete", "task_received"]
        
        hash_chain = [initial_hash]
        for event in events:
            self.sm.transition(event)
            hash_chain.append(self.sm.current_state_hash)
            
        # Verify hash chain integrity
        for i in range(1, len(hash_chain)):
            computed = hashlib.sha3_256(
                f"{hash_chain[i-1]}|{events[i-1]}".encode()
            ).hexdigest()
            self.assertEqual(hash_chain[i], computed)

    # --- Performance Tests ---
    def test_transition_throughput(self):
        """NIST SP 800-204 Section 6.2 Performance Benchmarking"""
        warmup_events = ["system_init", "config_complete"] * 1000
        for event in warmup_events:
            self.sm.transition(event)
        
        test_events = ["task_received", "task_completed"] * 5000
        with self.assertLogs(level="INFO") as log:
            for event in test_events:
                self.sm.transition(event)
                
        self.assertIn("TPS exceeding 2500/sec", log.output[0])

if __name__ == "__main__":
    unittest.main(
        failfast=True,
        buffer=True,
        catchbreak=False
    )
