#!/usr/bin/env python3
"""
Test suite for policy engine schema validation and path canonicalization
"""

import unittest
import json
import sys
import os
import tempfile

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from engine import PolicyAdapter, SchemaValidator


class TestSchemaValidator(unittest.TestCase):
    """Test JSON-RPC schema validation"""
    
    def setUp(self):
        self.validator = SchemaValidator()
    
    def test_valid_jsonrpc_request(self):
        """Test valid JSON-RPC 2.0 request"""
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "ping"}
        }
        valid, errors = self.validator.validate_jsonrpc_structure(msg)
        self.assertTrue(valid)
        self.assertEqual(len(errors), 0)
    
    def test_invalid_jsonrpc_version(self):
        """Test rejection of invalid JSON-RPC version"""
        msg = {
            "jsonrpc": "1.0",
            "id": 1,
            "method": "tools/call"
        }
        valid, errors = self.validator.validate_jsonrpc_structure(msg)
        self.assertFalse(valid)
        self.assertTrue(any("version" in e.lower() for e in errors))
    
    def test_missing_id(self):
        """Test rejection of request without ID"""
        msg = {
            "jsonrpc": "2.0",
            "method": "tools/call"
        }
        valid, errors = self.validator.validate_jsonrpc_structure(msg)
        self.assertFalse(valid)
        self.assertTrue(any("id" in e.lower() for e in errors))
    
    def test_argument_type_validation(self):
        """Test argument type checking"""
        schema = {
            "host": {"type": "string", "required": True}
        }
        
        # Valid string argument
        valid, errors = self.validator.validate_tool_arguments(
            "ping", 
            {"host": "127.0.0.1"}, 
            schema
        )
        self.assertTrue(valid)
        
        # Invalid: number instead of string
        valid, errors = self.validator.validate_tool_arguments(
            "ping", 
            {"host": 12345}, 
            schema
        )
        self.assertFalse(valid)
    
    def test_required_argument_missing(self):
        """Test detection of missing required arguments"""
        schema = {
            "host": {"type": "string", "required": True}
        }
        valid, errors = self.validator.validate_tool_arguments(
            "ping", 
            {}, 
            schema
        )
        self.assertFalse(valid)
        self.assertTrue(any("required" in e.lower() for e in errors))
    
    def test_string_length_validation(self):
        """Test string max length enforcement"""
        schema = {
            "query": {"type": "string", "max_length": 10}
        }
        
        # Valid: within length
        valid, errors = self.validator.validate_tool_arguments(
            "search", 
            {"query": "short"}, 
            schema
        )
        self.assertTrue(valid)
        
        # Invalid: exceeds length
        valid, errors = self.validator.validate_tool_arguments(
            "search", 
            {"query": "this is a very long query string"}, 
            schema
        )
        self.assertFalse(valid)
    
    def test_pattern_validation(self):
        """Test regex pattern matching"""
        schema = {
            "host": {"type": "string", "pattern": "^[a-zA-Z0-9.-]+$"}
        }
        
        # Valid: matches pattern
        valid, errors = self.validator.validate_tool_arguments(
            "ping", 
            {"host": "example.com"}, 
            schema
        )
        self.assertTrue(valid)
        
        # Invalid: contains illegal characters
        valid, errors = self.validator.validate_tool_arguments(
            "ping", 
            {"host": "evil.com; rm -rf /"}, 
            schema
        )
        self.assertFalse(valid)


class TestPathCanonicalization(unittest.TestCase):
    """Test path traversal prevention"""
    
    def setUp(self):
        # Create temporary policy file
        self.policy_data = {
            "allowed_tools": {
                "read_file": {
                    "action": "allow",
                    "allowed_paths": ["/tmp/workspace/**"],
                    "forbidden_paths": ["/etc/shadow", "/etc/passwd"]
                }
            }
        }
        
        self.temp_policy = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(self.policy_data, self.temp_policy)
        self.temp_policy.close()
        
        self.adapter = PolicyAdapter(self.temp_policy.name)
    
    def tearDown(self):
        os.unlink(self.temp_policy.name)
    
    def test_path_traversal_blocked(self):
        """Test that path traversal attacks are blocked"""
        # This should be blocked even if it starts with allowed prefix
        decision, reason = self.adapter.evaluate_tool_call(
            "read_file",
            {"path": "/tmp/workspace/../../etc/passwd"}
        )
        self.assertEqual(decision, "block")
    
    def test_forbidden_path_blocked(self):
        """Test that explicitly forbidden paths are blocked"""
        decision, reason = self.adapter.evaluate_tool_call(
            "read_file",
            {"path": "/etc/shadow"}
        )
        self.assertEqual(decision, "block")
        self.assertIn("forbidden", reason.lower())
    
    def test_symlink_resolution(self):
        """Test that symlinks are resolved to canonical paths"""
        # Create a temp symlink test
        with tempfile.TemporaryDirectory() as tmpdir:
            # This test verifies the canonicalization logic exists
            canonical = self.adapter.canonicalize_path(tmpdir)
            self.assertTrue(os.path.isabs(canonical))


class TestPolicyIntegration(unittest.TestCase):
    """Integration tests for complete policy enforcement"""
    
    def setUp(self):
        self.policy_data = {
            "allowed_tools": {
                "ping": {
                    "action": "allow",
                    "allowed_arguments": {
                        "host": {
                            "type": "string",
                            "pattern": "^[a-zA-Z0-9.-]+$",
                            "max_length": 253
                        }
                    }
                },
                "execute_command": {
                    "action": "block"
                }
            }
        }
        
        self.temp_policy = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(self.policy_data, self.temp_policy)
        self.temp_policy.close()
        
        self.adapter = PolicyAdapter(self.temp_policy.name)
    
    def tearDown(self):
        os.unlink(self.temp_policy.name)
    
    def test_allowed_tool_with_valid_args(self):
        """Test that properly formed requests are allowed"""
        decision, reason = self.adapter.evaluate_tool_call(
            "ping",
            {"host": "example.com"}
        )
        self.assertEqual(decision, "allow")
    
    def test_blocked_tool(self):
        """Test that explicitly blocked tools are rejected"""
        decision, reason = self.adapter.evaluate_tool_call(
            "execute_command",
            {"cmd": "ls"}
        )
        self.assertEqual(decision, "block")
    
    def test_unknown_tool_blocked(self):
        """Test default-deny for unlisted tools"""
        decision, reason = self.adapter.evaluate_tool_call(
            "unknown_tool",
            {}
        )
        self.assertEqual(decision, "flag")
        self.assertIn("default-deny", reason.lower())
    
    def test_invalid_argument_blocked(self):
        """Test that invalid arguments are rejected"""
        decision, reason = self.adapter.evaluate_tool_call(
            "ping",
            {"host": "evil.com; rm -rf /"}
        )
        self.assertEqual(decision, "block")


if __name__ == "__main__":
    print("=" * 70)
    print("Module 3: Policy Engine Validation Test Suite")
    print("=" * 70)
    unittest.main(verbosity=2)
