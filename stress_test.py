
import urllib.request

import ssl

import json

import time

from concurrent.futures import ThreadPoolExecutor, as_completed



CONCURRENT_REQUESTS = 200

TARGET_URL = "https://127.0.0.1:8443/mcp"



# Ignore self-signed certificate validation for localhost

ssl_context = ssl._create_unverified_context()



API_KEY = "qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE"

def send_request(req_id):
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": "ping", "arguments": {"host": "127.0.0.1", "seq": req_id}}
    }).encode("utf-8")

    req = urllib.request.Request(
        TARGET_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY
        }
    )

    

    try:

        with urllib.request.urlopen(req, context=ssl_context, timeout=5) as response:

            return req_id, response.read().decode("utf-8")

    except Exception as e:

        return req_id, f"Error: {e}"



def main():

    print(f"[*] Firing {CONCURRENT_REQUESTS} concurrent requests using built-in thread pool...")
    start_time = time.time()
    
    success_count = 0
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(send_request, i) for i in range(1, CONCURRENT_REQUESTS + 1)]
        for future in as_completed(futures):
            req_id, result = future.result()
            if not result.startswith("Error"):
                success_count += 1
                
    elapsed = time.time() - start_time
    print(f"[+] Finished {CONCURRENT_REQUESTS} calls in {elapsed:.2f}s ({success_count}/{CONCURRENT_REQUESTS} successful)")

if __name__ == "__main__":
    main()
