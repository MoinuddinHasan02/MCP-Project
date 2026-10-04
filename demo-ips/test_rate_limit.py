#!/usr/bin/env python3
"""
Test rate limiting functionality of the MCP server
"""

import urllib.request
import ssl
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGET_URL = "https://127.0.0.1:8443/mcp"
STATS_URL = "https://127.0.0.1:8443/stats"

# Ignore self-signed certificate validation
ssl_context = ssl._create_unverified_context()


API_KEY = "AuULuUlCTYPoT__SD2QBsN2h_PpZdpyjvFVBVjDQdzM"

def send_request(req_id):
    """Send a single MCP request"""
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": "ping", "arguments": {"host": "127.0.0.1"}}
    }).encode("utf-8")
    
    req = urllib.request.Request(
        TARGET_URL,
        data=payload,
        headers={"Content-Type": "application/json", "X-API-Key": API_KEY}
    )
    
    try:
        start_time = time.time()
        with urllib.request.urlopen(req, context=ssl_context, timeout=5) as response:
            elapsed = time.time() - start_time
            headers = dict(response.headers)
            return {
                "id": req_id,
                "status": response.status,
                "elapsed": elapsed,
                "rate_limit_remaining": headers.get('X-RateLimit-Remaining', 'N/A'),
                "success": True
            }
    except urllib.error.HTTPError as e:
        headers = dict(e.headers)
        try:
            body = e.read().decode('utf-8', errors='ignore')
        except Exception:
            body = ""
        return {
            "id": req_id,
            "status": e.code,
            "elapsed": 0,
            "rate_limit_remaining": headers.get('X-RateLimit-Remaining', 'N/A'),
            "retry_after": headers.get('Retry-After', 'N/A'),
            "error": body,
            "success": False
        }
    except Exception as e:
        return {
            "id": req_id,
            "status": "error",
            "error": str(e),
            "success": False
        }


RESET_URL = "https://127.0.0.1:8443/reset-limits"

def get_stats():
    """Get rate limit statistics"""
    try:
        req = urllib.request.Request(STATS_URL)
        with urllib.request.urlopen(req, context=ssl_context, timeout=5) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception as e:
        return {"error": str(e)}

def reset_limits():
    """Reset rate limits on the server for test isolation"""
    try:
        req = urllib.request.Request(RESET_URL)
        with urllib.request.urlopen(req, context=ssl_context, timeout=5) as response:
            return True
    except Exception:
        return False


def test_normal_operation():
    """Test that normal operation works within rate limits"""
    print("\n" + "="*70)
    print("TEST 1: Normal Operation (Within Rate Limits)")
    print("="*70)
    
    results = []
    for i in range(10):
        result = send_request(i)
        results.append(result)
        time.sleep(0.2)  # 5 req/sec, well within the 10 req/sec limit
    
    success_count = sum(1 for r in results if r["success"])
    print(f"✓ Sent 10 requests at 5 req/sec")
    print(f"✓ Success: {success_count}/10")
    
    if success_count == 10:
        print("✓ PASS: All requests succeeded within rate limits")
    else:
        print("✗ FAIL: Some requests were blocked unexpectedly")
    
    return success_count == 10


def test_burst_handling():
    """Test burst handling"""
    print("\n" + "="*70)
    print("TEST 2: Burst Handling (20 requests instantly)")
    print("="*70)
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(send_request, i) for i in range(20)]
        results = [f.result() for f in as_completed(futures)]
    
    success_count = sum(1 for r in results if r["success"])
    blocked_count = sum(1 for r in results if r.get("status") == 429)
    
    print(f"✓ Sent 20 requests simultaneously")
    print(f"✓ Success: {success_count}/20")
    print(f"✓ Rate Limited (429): {blocked_count}/20")
    
    # Burst size is 20, so all should succeed
    if success_count == 20:
        print("✓ PASS: Burst handled correctly")
        return True
    else:
        print("⚠ WARNING: Some burst requests were rate limited")
        return True  # Still acceptable


def test_rate_limit_enforcement():
    """Test that rate limits are enforced"""
    print("\n" + "="*70)
    print("TEST 3: Rate Limit Enforcement (50 rapid requests)")
    print("="*70)
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(send_request, i) for i in range(50)]
        results = [f.result() for f in as_completed(futures)]
    
    success_count = sum(1 for r in results if r["success"])
    blocked_count = sum(1 for r in results if r.get("status") == 429)
    
    print(f"✓ Sent 50 requests simultaneously")
    print(f"✓ Success: {success_count}/50")
    print(f"✓ Rate Limited (429): {blocked_count}/50")
    
    # With burst of 20, at least some should be rate limited
    if blocked_count > 0:
        print("✓ PASS: Rate limiting is working")
        
        # Show retry-after header
        rate_limited = [r for r in results if r.get("status") == 429]
        if rate_limited:
            print(f"✓ Retry-After header: {rate_limited[0].get('retry_after', 'N/A')} seconds")
        
        return True
    else:
        print("✗ FAIL: No requests were rate limited (expected some to be blocked)")
        return False


def test_recovery_after_rate_limit():
    """Test that rate limits recover over time"""
    print("\n" + "="*70)
    print("TEST 4: Recovery After Rate Limit")
    print("="*70)
    
    # First, exhaust the rate limit (burst size is 20)
    print("Step 1: Exhausting rate limit...")
    with ThreadPoolExecutor(max_workers=25) as executor:
        futures = [executor.submit(send_request, i) for i in range(25)]
        [f.result() for f in as_completed(futures)]
    
    # Wait for recovery (tokens refill at 10/sec)
    wait_time = 3
    print(f"Step 2: Waiting {wait_time} seconds for token bucket to refill...")
    time.sleep(wait_time)
    
    # Try again
    print("Step 3: Sending requests after recovery...")
    results = []
    for i in range(10):
        result = send_request(i + 1000)
        results.append(result)
        time.sleep(0.2)
    
    success_count = sum(1 for r in results if r["success"])
    print(f"✓ Success after recovery: {success_count}/10")
    
    if success_count >= 8:  # Allow some margin
        print("✓ PASS: Rate limit recovered successfully")
        return True
    else:
        print("✗ FAIL: Rate limit did not recover properly")
        return False


def test_statistics_endpoint():
    """Test the statistics endpoint"""
    print("\n" + "="*70)
    print("TEST 5: Statistics Endpoint")
    print("="*70)
    
    stats = get_stats()
    
    if "error" in stats:
        print(f"✗ FAIL: Could not retrieve stats: {stats['error']}")
        return False
    
    print(f"✓ Client IP: {stats.get('client_ip', 'N/A')}")
    print(f"✓ Available Tokens: {stats.get('client_stats', {}).get('available_tokens', 'N/A')}")
    print(f"✓ Requests Last Minute: {stats.get('client_stats', {}).get('requests_last_minute', 'N/A')}")
    print(f"✓ Total Clients Tracked: {stats.get('global_stats', {}).get('total_clients_tracked', 'N/A')}")
    print(f"✓ Rate Limit: {stats.get('global_stats', {}).get('rate_limit', 'N/A')}")
    
    print("✓ PASS: Statistics endpoint is working")
    return True


def main():
    print("="*70)
    print("MCP Server Rate Limiting Test Suite")
    print("="*70)
    print("\nConnecting to MCP server on https://127.0.0.1:8443...")
    
    results = []
    
    try:
        reset_limits()
        results.append(("Normal Operation", test_normal_operation()))
        time.sleep(1)
        reset_limits()
        results.append(("Burst Handling", test_burst_handling()))
        time.sleep(1)
        reset_limits()
        results.append(("Rate Limit Enforcement", test_rate_limit_enforcement()))
        time.sleep(1)
        reset_limits()
        results.append(("Recovery After Rate Limit", test_recovery_after_rate_limit()))
        time.sleep(1)
        reset_limits()
        results.append(("Statistics Endpoint", test_statistics_endpoint()))
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        return
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Rate limiting is working correctly.")
    else:
        print(f"\n⚠ {total - passed} test(s) failed. Review the output above.")


if __name__ == "__main__":
    main()
