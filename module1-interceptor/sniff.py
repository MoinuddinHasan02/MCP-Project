import sys, time, os

# Import secure temp manager
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'module3-policy'))
from secure_temp import get_secure_log_path

LOG = get_secure_log_path()
sys.stderr.write(f"[SYSTEM] TrueIntent eBPF engine listening on libssl.so...\n")
sys.stderr.write(f"[SYSTEM] Using secure log file: {LOG}\n")
sys.stderr.flush()

with open(LOG, 'r') as f:
    f.seek(0, os.SEEK_END)
    while True:
        line = f.readline()
        if line:
            print(line.strip())
            sys.stdout.flush()
        else:
            time.sleep(0.1)
