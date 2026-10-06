# TrueIntent Authentication System

## Overview

TrueIntent now requires authentication for all access:
- **MCP Server**: API key authentication (Bearer tokens)
- **Dashboard**: Basic HTTP authentication

## Initial Setup

When you first run TrueIntent with authentication enabled, it will automatically generate:
1. A default API key for the MCP server
2. Admin credentials for the dashboard

These credentials are displayed **once** and saved to `~/.trueintent/auth.json` with 0600 permissions.

```
🔐 TrueIntent Authentication Credentials
══════════════════════════════════════════════════════════════════════

MCP Server API Key: Abc123XyzDefGhiJklMno456PqrStuVwx789
Dashboard Username: admin
Dashboard Password: tK9$mL2@pH8#nQ5^

⚠️  SAVE THESE CREDENTIALS - They won't be shown again!
Config saved to: /home/user/.trueintent/auth.json
══════════════════════════════════════════════════════════════════════
```

## Using the MCP Server

### API Key Authentication

All requests to the MCP server must include an API key in one of two ways:

**Option 1: X-API-Key Header**
```bash
curl -k -X POST https://127.0.0.1:8443/mcp \
  -H "X-API-Key: YOUR_API_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ping","arguments":{"host":"127.0.0.1"}}}'
```

**Option 2: Authorization Bearer Header**
```bash
curl -k -X POST https://127.0.0.1:8443/mcp \
  -H "Authorization: Bearer YOUR_API_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ping","arguments":{"host":"127.0.0.1"}}}'
```

### Unauthenticated Request Response

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "Authentication required. Provide a valid API key in X-API-Key header or Authorization: Bearer header."
  }
}
```

HTTP Status: `401 Unauthorized`

## Accessing the Dashboard

The dashboard requires Basic HTTP authentication. Your browser will prompt for credentials:

**URL**: http://127.0.0.1:5000  
**Username**: admin (default)  
**Password**: [Generated during setup]

## Managing Authentication

### Command-Line Tool

Use the `auth.py` CLI to manage credentials:

```bash
cd module3-policy

# Initialize authentication (generates default credentials)
python3 auth.py init

# List all API keys
python3 auth.py list-keys

# Add a new API key
python3 auth.py add-api-key production "Production server key"

# Revoke an API key
python3 auth.py revoke-api-key production

# List dashboard users
python3 auth.py list-users

# Add a new dashboard user
python3 auth.py add-user developer user

# Remove a dashboard user
python3 auth.py remove-user developer

# Change a user's password
python3 auth.py change-password admin
```

### Programmatic Usage

```python
from auth import get_auth_manager

# Get the auth manager
auth_manager = get_auth_manager()

# Validate an API key
valid, key_name = auth_manager.validate_api_key("Abc123...")
if valid:
    print(f"Valid API key: {key_name}")

# Validate dashboard credentials
valid, role = auth_manager.validate_dashboard_credentials("admin", "password")
if valid:
    print(f"Valid user with role: {role}")

# Add a new API key
api_key = auth_manager.add_api_key("staging", "Staging environment key")
print(f"New API key: {api_key}")

# Add a new dashboard user
password = auth_manager.add_dashboard_user("analyst", role="user")
print(f"New user password: {password}")
```

## Security Features

### API Key Security
- **Generation**: Cryptographically secure random tokens (32 bytes)
- **Storage**: SHA-256 hashed, never stored in plaintext
- **Validation**: Constant-time comparison to prevent timing attacks
- **Format**: URL-safe Base64 encoded

### Password Security
- **Generation**: Cryptographically secure 20-character passwords
- **Hashing**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Salt**: 32-byte random salt per password
- **Validation**: Constant-time comparison

### Configuration File Security
- **Location**: `~/.trueintent/auth.json`
- **Permissions**: 0600 (owner read/write only)
- **Format**: JSON with hashed credentials only

## Authentication Flow

### MCP Server Request Flow
```
1. Client sends request with API key
   ↓
2. Server extracts key from header
   ↓
3. Key is hashed using SHA-256
   ↓
4. Hash is compared against stored hashes (constant-time)
   ↓
5. If valid: Process request
   If invalid: Return 401 Unauthorized
```

### Dashboard Access Flow
```
1. Browser requests dashboard
   ↓
2. Server sends 401 with WWW-Authenticate header
   ↓
3. Browser prompts for credentials
   ↓
4. Credentials sent as Base64-encoded Basic Auth
   ↓
5. Server decodes and validates using PBKDF2
   ↓
6. If valid: Serve dashboard
   If invalid: Return 401 again
```

## Rotation and Revocation

### Key Rotation Best Practices

1. **Regular Rotation**: Rotate API keys every 90 days
2. **Per-Environment Keys**: Use separate keys for dev/staging/prod
3. **Per-Service Keys**: Issue unique keys to different services
4. **Audit Trail**: Document when and why keys are issued/revoked

### Revoking Compromised Keys

If an API key is compromised:

```bash
# Immediately revoke the compromised key
python3 auth.py revoke-api-key compromised_key_name

# Generate a new key for the service
python3 auth.py add-api-key new_service_key "Replacement for compromised key"

# Update all clients with the new key
# Monitor logs for any usage of the old key
```

## Integration Examples

### Python Client

```python
import requests
import os

API_KEY = os.environ.get('TRUEINTENT_API_KEY')

response = requests.post(
    'https://127.0.0.1:8443/mcp',
    headers={
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json'
    },
    json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "ping",
            "arguments": {"host": "example.com"}
        }
    },
    verify=False  # Only for self-signed certs
)

print(response.json())
```

### JavaScript/Node.js Client

```javascript
const https = require('https');

const apiKey = process.env.TRUEINTENT_API_KEY;

const options = {
  hostname: '127.0.0.1',
  port: 8443,
  path: '/mcp',
  method: 'POST',
  headers: {
    'X-API-Key': apiKey,
    'Content-Type': 'application/json'
  },
  rejectUnauthorized: false // Only for self-signed certs
};

const req = https.request(options, (res) => {
  let data = '';
  res.on('data', (chunk) => { data += chunk; });
  res.on('end', () => { console.log(JSON.parse(data)); });
});

req.write(JSON.dumps({
  jsonrpc: '2.0',
  id: 1,
  method: 'tools/call',
  params: {
    name: 'ping',
    arguments: { host: 'example.com' }
  }
}));

req.end();
```

## Troubleshooting

### "Authentication required" Error

**Problem**: Getting 401 Unauthorized  
**Solution**:
- Verify API key is correct
- Check header name (X-API-Key or Authorization: Bearer)
- Ensure key hasn't been revoked
- Check auth.json file permissions (should be 0600)

### Dashboard Won't Accept Password

**Problem**: Credentials rejected by dashboard  
**Solution**:
- Verify username/password are correct
- Check browser isn't auto-filling old credentials
- Try resetting password: `python3 auth.py change-password admin`
- Check server logs for authentication errors

### Lost Credentials

**Problem**: Don't have access to original credentials  
**Solution**:

```bash
# Reset admin password
cd module3-policy
python3 auth.py change-password admin
# New password will be displayed

# Generate new API key
python3 auth.py add-api-key recovery "Recovery key"
# New key will be displayed

# Revoke old compromised keys
python3 auth.py revoke-api-key default
```

### Config File Corrupted

**Problem**: auth.json is damaged or missing  
**Solution**:

```bash
# Delete config and regenerate
rm ~/.trueintent/auth.json
python3 auth.py init
# New credentials will be generated
```

## Security Best Practices

1. ✅ **Store Keys Securely**
   - Use environment variables, not hardcoded strings
   - Use secret management systems (HashiCorp Vault, AWS Secrets Manager)
   - Never commit keys to version control

2. ✅ **Use HTTPS**
   - Always use TLS/SSL for MCP server communication
   - Verify certificate in production (don't skip verification)

3. ✅ **Monitor Authentication**
   - Review authentication logs regularly
   - Alert on repeated authentication failures
   - Track API key usage patterns

4. ✅ **Principle of Least Privilege**
   - Issue separate keys for different services
   - Revoke keys when no longer needed
   - Use dashboard "user" role for read-only access

5. ✅ **Regular Rotation**
   - Rotate API keys every 90 days
   - Change dashboard passwords periodically
   - Document rotation schedule

6. ❌ **Never Share Credentials**
   - Don't share API keys between environments
   - Don't share dashboard passwords between users
   - Issue unique credentials per user/service

## References

- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- NIST Digital Identity Guidelines: https://pages.nist.gov/800-63-3/
- API Security Best Practices: https://owasp.org/www-project-api-security/
