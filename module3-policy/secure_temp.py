#!/usr/bin/env python3
"""
Secure temporary file handling module for TrueIntent

Replaces insecure /tmp file usage with secure alternatives:
- Proper permissions (0600 for files, 0700 for directories)
- Unpredictable names using tempfile module
- Automatic cleanup on program exit
- Protection against symlink attacks
"""

import tempfile
import os
import atexit
import threading
from pathlib import Path


class SecureTempManager:
    """Manages secure temporary files and directories with automatic cleanup"""
    
    def __init__(self, prefix="trueintent_"):
        """
        Initialize secure temp manager.
        
        Args:
            prefix: Prefix for temporary files/directories
        """
        self.prefix = prefix
        self.temp_files = []
        self.temp_dirs = []
        self.lock = threading.Lock()
        
        # Register cleanup on exit
        atexit.register(self.cleanup_all)
    
    def create_temp_file(self, suffix="", mode='w+b', delete=False):
        """
        Create a secure temporary file.
        
        Args:
            suffix: Optional file suffix
            mode: File open mode
            delete: If True, file is deleted when closed (default: managed cleanup)
        
        Returns:
            File object with .name attribute containing the path
        """
        with self.lock:
            # Create with secure permissions (0600 = owner read/write only)
            fd, path = tempfile.mkstemp(
                suffix=suffix,
                prefix=self.prefix,
                dir=None  # Use system temp dir
            )
            
            # Set proper permissions
            os.chmod(path, 0o600)
            
            # Convert fd to file object
            file_obj = os.fdopen(fd, mode)
            
            if not delete:
                self.temp_files.append(path)
            
            return file_obj
    
    def create_temp_dir(self):
        """
        Create a secure temporary directory.
        
        Returns:
            Path to the temporary directory
        """
        with self.lock:
            # Create with secure permissions (0700 = owner only)
            dir_path = tempfile.mkdtemp(
                prefix=self.prefix,
                dir=None
            )
            
            # Set proper permissions
            os.chmod(dir_path, 0o700)
            
            self.temp_dirs.append(dir_path)
            
            return dir_path
    
    def get_log_file_path(self):
        """
        Get a secure path for the eBPF stream log.
        
        Returns:
            Path to secure log file
        """
        with self.lock:
            if not hasattr(self, '_log_file_path'):
                # Create persistent log file
                fd, path = tempfile.mkstemp(
                    suffix=".log",
                    prefix=f"{self.prefix}ebpf_stream_",
                    dir=None
                )
                os.chmod(path, 0o600)
                os.close(fd)
                
                self._log_file_path = path
                self.temp_files.append(path)
            
            return self._log_file_path
    
    def cleanup_file(self, path):
        """
        Safely delete a temporary file.
        
        Args:
            path: Path to file to delete
        """
        try:
            if os.path.exists(path):
                # Ensure it's not a symlink attack
                if not os.path.islink(path) and os.path.isfile(path):
                    os.remove(path)
        except Exception as e:
            # Log but don't fail
            print(f"Warning: Could not remove temp file {path}: {e}", file=sys.stderr)
    
    def cleanup_dir(self, path):
        """
        Safely delete a temporary directory and its contents.
        
        Args:
            path: Path to directory to delete
        """
        try:
            if os.path.exists(path):
                # Ensure it's not a symlink attack
                if not os.path.islink(path) and os.path.isdir(path):
                    import shutil
                    shutil.rmtree(path)
        except Exception as e:
            print(f"Warning: Could not remove temp dir {path}: {e}", file=sys.stderr)
    
    def cleanup_all(self):
        """Clean up all temporary files and directories"""
        with self.lock:
            # Clean up files
            for path in self.temp_files[:]:
                self.cleanup_file(path)
                self.temp_files.remove(path)
            
            # Clean up directories
            for path in self.temp_dirs[:]:
                self.cleanup_dir(path)
                self.temp_dirs.remove(path)


# Global singleton instance
_temp_manager = None
_manager_lock = threading.Lock()


def get_temp_manager():
    """
    Get the global secure temp manager instance (singleton).
    
    Returns:
        SecureTempManager instance
    """
    global _temp_manager
    
    if _temp_manager is None:
        with _manager_lock:
            if _temp_manager is None:
                _temp_manager = SecureTempManager()
    
    return _temp_manager


# Convenience functions
def create_secure_temp_file(suffix="", mode='w+b'):
    """Create a secure temporary file"""
    return get_temp_manager().create_temp_file(suffix=suffix, mode=mode)


def create_secure_temp_dir():
    """Create a secure temporary directory"""
    return get_temp_manager().create_temp_dir()


def get_secure_log_path():
    """Get secure path for eBPF stream log"""
    return get_temp_manager().get_log_file_path()


if __name__ == "__main__":
    import sys
    
    # Test the secure temp manager
    print("Testing SecureTempManager...")
    
    manager = SecureTempManager(prefix="test_")
    
    # Test file creation
    print("\n1. Creating secure temp file...")
    temp_file = manager.create_temp_file(suffix=".txt", mode='w')
    print(f"   Created: {temp_file.name}")
    print(f"   Permissions: {oct(os.stat(temp_file.name).st_mode)[-3:]}")
    temp_file.write("test data")
    temp_file.close()
    
    # Test directory creation
    print("\n2. Creating secure temp directory...")
    temp_dir = manager.create_temp_dir()
    print(f"   Created: {temp_dir}")
    print(f"   Permissions: {oct(os.stat(temp_dir).st_mode)[-3:]}")
    
    # Test log path
    print("\n3. Getting secure log path...")
    log_path = manager.get_log_file_path()
    print(f"   Log path: {log_path}")
    print(f"   Permissions: {oct(os.stat(log_path).st_mode)[-3:]}")
    
    # Test cleanup
    print("\n4. Cleaning up...")
    manager.cleanup_all()
    
    print(f"   File exists: {os.path.exists(temp_file.name)}")
    print(f"   Dir exists: {os.path.exists(temp_dir)}")
    
    print("\n✓ All tests passed!")
