#!/usr/bin/env python3
"""
Authentication module for TrueIntent MCP Security Firewall

Provides:
- API key authentication for MCP server
- Basic authentication for dashboard
- Secure key generation and storage
"""

import hashlib
import hmac
import secrets
import json
import os
import base64
from pathlib import Path


class AuthManager:
    """Manages authentication for MCP server and dashboard"""
    
    def __init__(self, config_path=None):
        """
        Initialize authentication manager.
        
        Args:
            config_path: Path to auth configuration file
        """
        if config_path is None:
            if "TRUEINTENT_AUTH_CONFIG" in os.environ:
                config_path = Path(os.environ["TRUEINTENT_AUTH_CONFIG"])
            elif "SUDO_USER" in os.environ and Path(f"/home/{os.environ['SUDO_USER']}/.trueintent/auth.json").exists():
                config_path = Path(f"/home/{os.environ['SUDO_USER']}/.trueintent/auth.json")
            else:
                config_path = Path.home() / ".trueintent" / "auth.json"
        
        self.config_path = Path(config_path)
        self.config = self._load_or_create_config()
    
    def _load_or_create_config(self):
        """Load existing config or create new one with secure defaults"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                return config
        else:
            # Create new configuration with secure defaults
            config = {
                "mcp_api_keys": {},
                "dashboard_users": {},
                "key_rotation_days": 90,
                "created_at": None
            }
            
            # Generate initial API key
            api_key = self.generate_api_key()
            config["mcp_api_keys"]["default"] = {
                "key_hash": self._hash_key(api_key),
                "created_at": self._timestamp(),
                "description": "Default API key"
            }
            
            # Generate initial dashboard credentials
            username = "admin"
            password = self.generate_password()
            config["dashboard_users"][username] = {
                "password_hash": self._hash_password(password),
                "created_at": self._timestamp(),
                "role": "admin"
            }
            
            config["created_at"] = self._timestamp()
            
            # Save configuration
            self._save_config(config)
            
            # Print credentials (only shown once)
            print("\n" + "="*70)
            print("🔐 TrueIntent Authentication Credentials")
            print("="*70)
            print(f"\nMCP Server API Key: {api_key}")
            print(f"Dashboard Username: {username}")
            print(f"Dashboard Password: {password}")
            print(f"\n⚠️  SAVE THESE CREDENTIALS - They won't be shown again!")
            print(f"Config saved to: {self.config_path}")
            print("="*70 + "\n")
            
            return config
    
    def _save_config(self, config):
        """Save configuration to file with secure permissions"""
        # Create directory if it doesn't exist
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write config
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Set secure permissions (owner read/write only)
        os.chmod(self.config_path, 0o600)
    
    def _timestamp(self):
        """Get current timestamp"""
        import time
        return int(time.time())
    
    def _hash_key(self, key):
        """Hash an API key using SHA-256"""
        return hashlib.sha256(key.encode()).hexdigest()
    
    def _hash_password(self, password):
        """Hash a password using PBKDF2-HMAC-SHA256"""
        salt = secrets.token_bytes(32)
        hash_value = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000  # iterations
        )
        # Store salt and hash together
        combined = salt + hash_value
        return base64.b64encode(combined).decode('ascii')
    
    def _verify_password(self, password, password_hash):
        """Verify a password against its hash"""
        combined = base64.b64decode(password_hash.encode('ascii'))
        salt = combined[:32]
        stored_hash = combined[32:]
        
        computed_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000
        )
        
        return hmac.compare_digest(stored_hash, computed_hash)
    
    def generate_api_key(self, length=32):
        """Generate a cryptographically secure API key"""
        return secrets.token_urlsafe(length)
    
    def generate_password(self, length=20):
        """Generate a cryptographically secure password"""
        # Use alphanumeric + special characters
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def validate_api_key(self, api_key):
        """
        Validate an API key.
        
        Args:
            api_key: API key to validate
        
        Returns:
            (valid, key_name) tuple
        """
        if not api_key:
            return False, None
        
        key_hash = self._hash_key(api_key)
        
        for key_name, key_data in self.config.get("mcp_api_keys", {}).items():
            if hmac.compare_digest(key_data["key_hash"], key_hash):
                return True, key_name

        # Reload from disk if not found (in case keys were added or rotated)
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
                for key_name, key_data in self.config.get("mcp_api_keys", {}).items():
                    if hmac.compare_digest(key_data["key_hash"], key_hash):
                        return True, key_name
            except Exception:
                pass
        
        return False, None
    
    def validate_dashboard_credentials(self, username, password):
        """
        Validate dashboard credentials.
        
        Args:
            username: Username
            password: Password
        
        Returns:
            (valid, role) tuple
        """
        if not username or not password:
            return False, None
        
        user_data = self.config["dashboard_users"].get(username)
        if not user_data:
            return False, None
        
        if self._verify_password(password, user_data["password_hash"]):
            return True, user_data.get("role", "user")
        
        return False, None
    
    def add_api_key(self, key_name, description=""):
        """
        Add a new API key.
        
        Args:
            key_name: Name for the API key
            description: Description of the key's purpose
        
        Returns:
            Generated API key (string)
        """
        api_key = self.generate_api_key()
        
        self.config["mcp_api_keys"][key_name] = {
            "key_hash": self._hash_key(api_key),
            "created_at": self._timestamp(),
            "description": description
        }
        
        self._save_config(self.config)
        
        return api_key
    
    def revoke_api_key(self, key_name):
        """Revoke an API key"""
        if key_name in self.config["mcp_api_keys"]:
            del self.config["mcp_api_keys"][key_name]
            self._save_config(self.config)
            return True
        return False
    
    def add_dashboard_user(self, username, role="user"):
        """
        Add a new dashboard user.
        
        Args:
            username: Username
            role: User role (admin or user)
        
        Returns:
            Generated password (string)
        """
        password = self.generate_password()
        
        self.config["dashboard_users"][username] = {
            "password_hash": self._hash_password(password),
            "created_at": self._timestamp(),
            "role": role
        }
        
        self._save_config(self.config)
        
        return password
    
    def remove_dashboard_user(self, username):
        """Remove a dashboard user"""
        if username in self.config["dashboard_users"]:
            del self.config["dashboard_users"][username]
            self._save_config(self.config)
            return True
        return False
    
    def change_password(self, username, new_password):
        """Change a dashboard user's password"""
        if username in self.config["dashboard_users"]:
            self.config["dashboard_users"][username]["password_hash"] = self._hash_password(new_password)
            self._save_config(self.config)
            return True
        return False
    
    def list_api_keys(self):
        """List all API keys (without revealing the keys)"""
        return {
            name: {
                "description": data.get("description", ""),
                "created_at": data.get("created_at")
            }
            for name, data in self.config["mcp_api_keys"].items()
        }
    
    def list_dashboard_users(self):
        """List all dashboard users"""
        return {
            name: {
                "role": data.get("role", "user"),
                "created_at": data.get("created_at")
            }
            for name, data in self.config["dashboard_users"].items()
        }


# Global singleton
_auth_manager = None


def get_auth_manager():
    """Get the global authentication manager instance"""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager()
    return _auth_manager


if __name__ == "__main__":
    import sys
    
    # CLI for managing authentication
    if len(sys.argv) < 2:
        print("TrueIntent Authentication Manager")
        print("\nUsage:")
        print("  python auth.py init              - Initialize authentication")
        print("  python auth.py add-api-key <name> <desc>  - Add new API key")
        print("  python auth.py revoke-api-key <name>      - Revoke API key")
        print("  python auth.py add-user <username> <role> - Add dashboard user")
        print("  python auth.py remove-user <username>     - Remove dashboard user")
        print("  python auth.py change-password <username> - Change user password")
        print("  python auth.py list-keys         - List API keys")
        print("  python auth.py list-users        - List dashboard users")
        sys.exit(1)
    
    command = sys.argv[1]
    manager = get_auth_manager()
    
    if command == "init":
        print("Authentication initialized!")
    
    elif command == "add-api-key":
        if len(sys.argv) < 4:
            print("Usage: python auth.py add-api-key <name> <description>")
            sys.exit(1)
        name = sys.argv[2]
        description = sys.argv[3]
        api_key = manager.add_api_key(name, description)
        print(f"✓ API Key '{name}' created: {api_key}")
    
    elif command == "revoke-api-key":
        if len(sys.argv) < 3:
            print("Usage: python auth.py revoke-api-key <name>")
            sys.exit(1)
        name = sys.argv[2]
        if manager.revoke_api_key(name):
            print(f"✓ API Key '{name}' revoked")
        else:
            print(f"✗ API Key '{name}' not found")
    
    elif command == "add-user":
        if len(sys.argv) < 4:
            print("Usage: python auth.py add-user <username> <role>")
            sys.exit(1)
        username = sys.argv[2]
        role = sys.argv[3]
        password = manager.add_dashboard_user(username, role)
        print(f"✓ User '{username}' created with password: {password}")
    
    elif command == "remove-user":
        if len(sys.argv) < 3:
            print("Usage: python auth.py remove-user <username>")
            sys.exit(1)
        username = sys.argv[2]
        if manager.remove_dashboard_user(username):
            print(f"✓ User '{username}' removed")
        else:
            print(f"✗ User '{username}' not found")
    
    elif command == "change-password":
        if len(sys.argv) < 3:
            print("Usage: python auth.py change-password <username>")
            sys.exit(1)
        username = sys.argv[2]
        new_password = manager.generate_password()
        if manager.change_password(username, new_password):
            print(f"✓ Password changed for '{username}': {new_password}")
        else:
            print(f"✗ User '{username}' not found")
    
    elif command == "list-keys":
        keys = manager.list_api_keys()
        print("\nAPI Keys:")
        for name, data in keys.items():
            print(f"  - {name}: {data['description']}")
    
    elif command == "list-users":
        users = manager.list_dashboard_users()
        print("\nDashboard Users:")
        for username, data in users.items():
            print(f"  - {username} ({data['role']})")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
