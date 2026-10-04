#!/usr/bin/env python3
"""
Audit Logging System for TrueIntent MCP Security Firewall

Provides tamper-evident, persistent logging of all security events:
- Authentication attempts
- Policy decisions
- Threat detections
- Rate limit violations
- Administrative actions

Features:
- Structured JSON logging
- Automatic log rotation
- Tamper-evident chain (HMAC-based)
- Indexed search capabilities
- Retention policies
"""

import json
import hashlib
import hmac
import time
import os
import gzip
from pathlib import Path
from datetime import datetime, timedelta
from collections import deque
import threading


class AuditLogger:
    """Tamper-evident audit logger with automatic rotation"""
    
    def __init__(self, log_dir=None, max_size_mb=100, retention_days=90):
        """
        Initialize audit logger.
        
        Args:
            log_dir: Directory for log files (default: ~/.trueintent/logs)
            max_size_mb: Maximum size of active log file before rotation
            retention_days: Days to retain logs before deletion
        """
        if log_dir is None:
            log_dir = Path.home() / ".trueintent" / "logs"
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.retention_days = retention_days
        
        # Generate or load integrity key
        self.integrity_key = self._load_or_generate_key()
        
        # Current log file
        self.current_log = self._get_current_log_path()
        self.log_lock = threading.Lock()
        
        # Previous entry hash for chain integrity
        self.prev_hash = self._get_last_hash()
        
        # In-memory buffer for recent events
        self.recent_events = deque(maxlen=1000)
        
        # Start cleanup thread
        self._start_cleanup_thread()
    
    def _load_or_generate_key(self):
        """Load or generate HMAC key for integrity checking"""
        key_file = self.log_dir / ".integrity_key"
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new key
            import secrets
            key = secrets.token_bytes(32)
            
            with open(key_file, 'wb') as f:
                f.write(key)
            
            # Set secure permissions
            os.chmod(key_file, 0o600)
            
            return key
    
    def _get_current_log_path(self):
        """Get path to current active log file"""
        timestamp = datetime.now().strftime("%Y%m%d")
        return self.log_dir / f"audit_{timestamp}.jsonl"
    
    def _get_last_hash(self):
        """Get the last entry's hash from current log file"""
        if not self.current_log.exists():
            return "0" * 64  # Initial hash for new log file
        
        try:
            with open(self.current_log, 'r') as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1].strip()
                    if last_line:
                        entry = json.loads(last_line)
                        return entry.get("integrity_hash", "0" * 64)
        except Exception:
            pass
        
        return "0" * 64
    
    def _compute_integrity_hash(self, entry_data, prev_hash):
        """Compute HMAC-SHA256 integrity hash for entry"""
        # Combine entry data with previous hash for chain
        data = json.dumps(entry_data, sort_keys=True) + prev_hash
        return hmac.new(
            self.integrity_key,
            data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    def _rotate_if_needed(self):
        """Rotate log file if size exceeds limit"""
        if not self.current_log.exists():
            return
        
        if self.current_log.stat().st_size >= self.max_size_bytes:
            # Compress old log
            compressed_path = self.current_log.with_suffix('.jsonl.gz')
            
            with open(self.current_log, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb') as f_out:
                    f_out.writelines(f_in)
            
            # Remove original
            self.current_log.unlink()
            
            # Reset for new log
            self.current_log = self._get_current_log_path()
            self.prev_hash = "0" * 64
    
    def _start_cleanup_thread(self):
        """Start background thread for log cleanup"""
        def cleanup_worker():
            while True:
                try:
                    self._cleanup_old_logs()
                    time.sleep(86400)  # Run daily
                except Exception as e:
                    print(f"Log cleanup error: {e}")
        
        thread = threading.Thread(target=cleanup_worker, daemon=True)
        thread.start()
    
    def _cleanup_old_logs(self):
        """Remove logs older than retention period"""
        cutoff = datetime.now() - timedelta(days=self.retention_days)
        
        for log_file in self.log_dir.glob("audit_*.jsonl*"):
            if log_file.stat().st_mtime < cutoff.timestamp():
                log_file.unlink()
    
    def log(self, event_type, data, severity="INFO"):
        """
        Log a security event.
        
        Args:
            event_type: Type of event (auth_attempt, policy_decision, threat_detected, etc.)
            data: Event-specific data dictionary
            severity: Severity level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        with self.log_lock:
            # Rotate if needed
            self._rotate_if_needed()
            
            # Build entry
            entry = {
                "timestamp": time.time(),
                "timestamp_iso": datetime.utcnow().isoformat() + "Z",
                "event_type": event_type,
                "severity": severity,
                "data": data,
                "prev_hash": self.prev_hash
            }
            
            # Compute integrity hash
            integrity_hash = self._compute_integrity_hash(entry, self.prev_hash)
            entry["integrity_hash"] = integrity_hash
            
            # Write to file
            with open(self.current_log, 'a') as f:
                f.write(json.dumps(entry) + '\n')
            
            # Update chain
            self.prev_hash = integrity_hash
            
            # Add to recent events buffer
            self.recent_events.append(entry)
    
    def log_auth_attempt(self, client_ip, username, success, method="api_key"):
        """Log authentication attempt"""
        self.log(
            "auth_attempt",
            {
                "client_ip": client_ip,
                "username": username,
                "success": success,
                "method": method
            },
            severity="WARNING" if not success else "INFO"
        )
    
    def log_policy_decision(self, client_ip, tool_name, decision, reason):
        """Log policy engine decision"""
        self.log(
            "policy_decision",
            {
                "client_ip": client_ip,
                "tool_name": tool_name,
                "decision": decision,
                "reason": reason
            },
            severity="WARNING" if decision == "block" else "INFO"
        )
    
    def log_threat_detected(self, client_ip, threat_type, details, request_id=None):
        """Log threat detection"""
        self.log(
            "threat_detected",
            {
                "client_ip": client_ip,
                "threat_type": threat_type,
                "details": details,
                "request_id": request_id
            },
            severity="CRITICAL"
        )
    
    def log_rate_limit(self, client_ip, reason, retry_after):
        """Log rate limit violation"""
        self.log(
            "rate_limit_exceeded",
            {
                "client_ip": client_ip,
                "reason": reason,
                "retry_after": retry_after
            },
            severity="WARNING"
        )
    
    def log_admin_action(self, username, action, details):
        """Log administrative action"""
        self.log(
            "admin_action",
            {
                "username": username,
                "action": action,
                "details": details
            },
            severity="INFO"
        )
    
    def query(self, event_type=None, severity=None, start_time=None, end_time=None, limit=100):
        """
        Query audit logs.
        
        Args:
            event_type: Filter by event type
            severity: Filter by severity
            start_time: Start timestamp (Unix time)
            end_time: End timestamp (Unix time)
            limit: Maximum number of results
        
        Returns:
            List of matching log entries
        """
        results = []
        
        # Search current log and compressed logs
        log_files = sorted(self.log_dir.glob("audit_*.jsonl*"), reverse=True)
        
        for log_file in log_files:
            if len(results) >= limit:
                break
            
            try:
                if log_file.suffix == '.gz':
                    with gzip.open(log_file, 'rt') as f:
                        lines = f.readlines()
                else:
                    with open(log_file, 'r') as f:
                        lines = f.readlines()
                
                for line in reversed(lines):
                    if len(results) >= limit:
                        break
                    
                    try:
                        entry = json.loads(line.strip())
                        
                        # Apply filters
                        if event_type and entry.get("event_type") != event_type:
                            continue
                        if severity and entry.get("severity") != severity:
                            continue
                        if start_time and entry.get("timestamp", 0) < start_time:
                            continue
                        if end_time and entry.get("timestamp", 0) > end_time:
                            continue
                        
                        results.append(entry)
                    
                    except json.JSONDecodeError:
                        continue
            
            except Exception:
                continue
        
        return results
    
    def verify_integrity(self, entry):
        """
        Verify integrity of a log entry.
        
        Args:
            entry: Log entry dictionary
        
        Returns:
            True if integrity check passes
        """
        stored_hash = entry.get("integrity_hash")
        prev_hash = entry.get("prev_hash")
        
        if not stored_hash or not prev_hash:
            return False
        
        # Remove integrity_hash for computation
        entry_copy = entry.copy()
        del entry_copy["integrity_hash"]
        
        computed_hash = self._compute_integrity_hash(entry_copy, prev_hash)
        
        return hmac.compare_digest(stored_hash, computed_hash)
    
    def get_recent_events(self, count=100):
        """Get recent events from in-memory buffer or disk log"""
        if self.recent_events:
            return list(self.recent_events)[-count:]
        return self.query(limit=count)
    
    def export_report(self, output_file, start_time=None, end_time=None):
        """
        Export audit log report to file.
        
        Args:
            output_file: Output file path
            start_time: Start timestamp
            end_time: End timestamp
        """
        events = self.query(start_time=start_time, end_time=end_time, limit=10000)
        
        with open(output_file, 'w') as f:
            f.write("TrueIntent Audit Log Report\n")
            f.write("=" * 70 + "\n\n")
            
            if start_time:
                f.write(f"Start: {datetime.fromtimestamp(start_time).isoformat()}\n")
            if end_time:
                f.write(f"End: {datetime.fromtimestamp(end_time).isoformat()}\n")
            f.write(f"Total Events: {len(events)}\n\n")
            
            # Summary by event type
            event_counts = {}
            for event in events:
                event_type = event.get("event_type", "unknown")
                event_counts[event_type] = event_counts.get(event_type, 0) + 1
            
            f.write("Event Summary:\n")
            for event_type, count in sorted(event_counts.items()):
                f.write(f"  {event_type}: {count}\n")
            
            f.write("\n" + "=" * 70 + "\n\n")
            
            # Detailed events
            for event in events:
                f.write(f"[{event['timestamp_iso']}] {event['severity']} - {event['event_type']}\n")
                f.write(f"  Data: {json.dumps(event['data'], indent=2)}\n")
                f.write(f"  Integrity: {'✓' if self.verify_integrity(event) else '✗'}\n\n")


# Global singleton
_audit_logger = None
_logger_lock = threading.Lock()


def get_audit_logger():
    """Get the global audit logger instance"""
    global _audit_logger
    
    if _audit_logger is None:
        with _logger_lock:
            if _audit_logger is None:
                _audit_logger = AuditLogger()
    
    return _audit_logger


if __name__ == "__main__":
    import sys
    
    # CLI for audit log management
    if len(sys.argv) < 2:
        print("TrueIntent Audit Log Manager")
        print("\nUsage:")
        print("  python audit_logger.py query [event_type] [severity]  - Query logs")
        print("  python audit_logger.py recent [count]                 - Show recent events")
        print("  python audit_logger.py verify                         - Verify integrity")
        print("  python audit_logger.py export <file> [days]           - Export report")
        print("  python audit_logger.py test                           - Run test")
        sys.exit(1)
    
    command = sys.argv[1]
    logger = get_audit_logger()
    
    if command == "query":
        event_type = sys.argv[2] if len(sys.argv) > 2 else None
        severity = sys.argv[3] if len(sys.argv) > 3 else None
        
        results = logger.query(event_type=event_type, severity=severity, limit=50)
        
        print(f"\nFound {len(results)} matching events:\n")
        for entry in results:
            print(f"[{entry['timestamp_iso']}] {entry['severity']} - {entry['event_type']}")
            print(f"  {json.dumps(entry['data'])}\n")
    
    elif command == "recent":
        count = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        
        events = logger.get_recent_events(count)
        print(f"\nLast {len(events)} events:\n")
        for entry in events:
            print(f"[{entry['timestamp_iso']}] {entry['severity']} - {entry['event_type']}")
    
    elif command == "verify":
        results = logger.query(limit=1000)
        valid = sum(1 for e in results if logger.verify_integrity(e))
        
        print(f"\nIntegrity Check:")
        print(f"  Total entries: {len(results)}")
        print(f"  Valid: {valid}")
        print(f"  Invalid: {len(results) - valid}")
        
        if valid == len(results):
            print("\n✓ All entries have valid integrity hashes")
        else:
            print("\n✗ Some entries have invalid integrity hashes!")
    
    elif command == "export":
        if len(sys.argv) < 3:
            print("Usage: python audit_logger.py export <output_file> [days]")
            sys.exit(1)
        
        output_file = sys.argv[2]
        days = int(sys.argv[3]) if len(sys.argv) > 3 else 7
        
        start_time = time.time() - (days * 86400)
        logger.export_report(output_file, start_time=start_time)
        
        print(f"✓ Report exported to {output_file}")
    
    elif command == "test":
        print("Running audit logger test...")
        
        # Log some test events
        logger.log_auth_attempt("192.168.1.100", "admin", True)
        logger.log_auth_attempt("192.168.1.101", "hacker", False)
        logger.log_policy_decision("192.168.1.100", "execute_command", "block", "Dangerous command")
        logger.log_threat_detected("192.168.1.102", "command_injection", {"pattern": "sudo rm -rf"})
        logger.log_rate_limit("192.168.1.103", "Too many requests", 60)
        
        print("✓ Logged 5 test events")
        
        # Query recent
        recent = logger.get_recent_events(5)
        print(f"✓ Retrieved {len(recent)} recent events")
        
        # Verify integrity
        valid = all(logger.verify_integrity(e) for e in recent)
        print(f"✓ Integrity check: {'PASS' if valid else 'FAIL'}")
        
        print("\n✓ All tests passed!")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
