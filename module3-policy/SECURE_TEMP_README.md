# Secure Temporary File Handling

## Overview

TrueIntent now uses a secure temporary file management system to prevent security vulnerabilities associated with predictable file paths in shared directories like `/tmp`.

## Security Issues Addressed

### Previous Implementation (INSECURE)
```python
# ❌ INSECURE - Predictable path
LOG = '/tmp/trueintent_ebpf_stream.log'

# ❌ INSECURE - World-readable permissions
chmod 666 /tmp/trueintent_ebpf_stream.log

# ❌ INSECURE - Vulnerable to symlink attacks
with open("/tmp/trueintent_abort.signal", "w") as f:
    f.write("abort")
```

**Vulnerabilities:**
1. **Predictable Paths**: Attackers can predict file locations
2. **Permission Issues**: World-readable/writable files leak information
3. **Symlink Attacks**: Malicious users can create symlinks to sensitive files
4. **Race Conditions**: Multiple instances can conflict
5. **No Cleanup**: Temporary files persist after program exit

### Current Implementation (SECURE)
```python
# ✅ SECURE - Unpredictable path
from secure_temp import get_secure_log_path
LOG = get_secure_log_path()

# ✅ SECURE - Owner-only permissions (0600)
# Automatically set by secure_temp module

# ✅ SECURE - Symlink protection
# Validation ensures real files, not symlinks
```

**Security Features:**
1. **Unpredictable Paths**: Uses `tempfile.mkstemp()` for random names
2. **Restrictive Permissions**: Files created with 0600 (owner read/write only)
3. **Symlink Protection**: Validates files before operations
4. **Automatic Cleanup**: `atexit` handler ensures cleanup
5. **Thread-Safe**: Locks prevent race conditions

## Usage

### Creating a Secure Temporary File

```python
from secure_temp import create_secure_temp_file

# Create a secure temp file
temp_file = create_secure_temp_file(suffix=".log", mode='w')
temp_file.write("Secure data")
print(f"File created at: {temp_file.name}")
temp_file.close()

# File has permissions 0600 (owner read/write only)
# Automatically cleaned up on program exit
```

### Creating a Secure Temporary Directory

```python
from secure_temp import create_secure_temp_dir

# Create a secure temp directory
temp_dir = create_secure_temp_dir()
print(f"Directory created at: {temp_dir}")

# Directory has permissions 0700 (owner only)
# Automatically cleaned up on program exit
```

### Getting the Secure Log Path (Singleton)

```python
from secure_temp import get_secure_log_path

# Get the secure log file path (same across multiple calls)
log_path = get_secure_log_path()

# Use for eBPF stream logging
with open(log_path, 'a') as f:
    f.write("Log entry\n")
```

### Manual Cleanup

```python
from secure_temp import get_temp_manager

manager = get_temp_manager()

# Clean up specific file
manager.cleanup_file("/path/to/temp/file")

# Clean up all managed temp files
manager.cleanup_all()
```

## Files Updated

The following files have been updated to use secure temporary file handling:

1. **module1-interceptor/sniff.py**
   - Now uses `get_secure_log_path()` instead of `/tmp/trueintent_ebpf_stream.log`

2. **demo-ips/agent_cloud.py**
   - Replaced insecure abort signal with request-ID-based blocking
   - Uses secure log path

3. **demo-ips/dashboard.py**
   - Removed insecure `/tmp/trueintent_abort.signal` file
   - Now relies on server's request-ID blocking mechanism

4. **run_all.sh**
   - Removed manual log file creation with insecure permissions
   - Let secure_temp module handle file creation automatically

## Migration Guide

If you have custom code using the old `/tmp` files:

### Old Code (Insecure)
```python
# Reading log
with open('/tmp/trueintent_ebpf_stream.log', 'r') as f:
    data = f.read()

# Writing signal
with open('/tmp/trueintent_abort.signal', 'w') as f:
    f.write('abort')
```

### New Code (Secure)
```python
from secure_temp import get_secure_log_path

# Reading log
log_path = get_secure_log_path()
with open(log_path, 'r') as f:
    data = f.read()

# Blocking requests - use request-ID mechanism instead
# See demo-ips/server.py for the new blocking API
```

## Testing

Run the test suite to verify secure temp handling:

```bash
cd module3-policy
python3 secure_temp.py
```

Expected output:
```
Testing SecureTempManager...

1. Creating secure temp file...
   Created: /tmp/trueintent_abc123.txt
   Permissions: 600

2. Creating secure temp directory...
   Created: /tmp/trueintent_xyz789
   Permissions: 700

3. Getting secure log path...
   Log path: /tmp/trueintent_ebpf_stream_def456.log
   Permissions: 600

4. Cleaning up...
   File exists: False
   Dir exists: False

✓ All tests passed!
```

## Security Checklist

When working with temporary files in TrueIntent:

- ✅ Always use `secure_temp` module for temporary files
- ✅ Never hardcode paths in `/tmp`
- ✅ Verify file permissions are 0600 or 0700
- ✅ Check for symlinks before file operations
- ✅ Use thread-safe operations for shared resources
- ✅ Ensure automatic cleanup on exit
- ❌ Never use world-readable permissions (666, 777)
- ❌ Never use predictable filenames
- ❌ Never skip symlink validation

## Best Practices

1. **Use the Singleton Pattern for Shared Logs**
   ```python
   # Good - same log across entire application
   log_path = get_secure_log_path()
   ```

2. **Let the Manager Handle Cleanup**
   ```python
   # Good - automatic cleanup
   temp_file = create_secure_temp_file()
   
   # Not needed - cleanup is automatic
   # manager.cleanup_file(temp_file.name)
   ```

3. **Check Permissions After Creation**
   ```python
   import os
   temp_file = create_secure_temp_file()
   perms = oct(os.stat(temp_file.name).st_mode)[-3:]
   assert perms == '600', f"Insecure permissions: {perms}"
   ```

## Troubleshooting

### Permission Denied Errors

If you see permission denied errors:
- Ensure the process has write access to system temp directory
- Check that SELinux/AppArmor policies allow temp file creation

### Cleanup Issues

If temp files aren't being cleaned up:
- Check that the program exits normally (not killed with SIGKILL)
- Verify `atexit` handlers are being called
- Manually call `cleanup_all()` in signal handlers if needed

### Path Not Found

If the log path doesn't exist:
- The log file is created lazily on first access
- Ensure `get_secure_log_path()` is called before trying to read
- Check file system permissions

## References

- Python `tempfile` module: https://docs.python.org/3/library/tempfile.html
- OWASP Insecure Temporary File: https://owasp.org/www-community/vulnerabilities/Insecure_Temporary_File
- CWE-377: Insecure Temporary File: https://cwe.mitre.org/data/definitions/377.html
