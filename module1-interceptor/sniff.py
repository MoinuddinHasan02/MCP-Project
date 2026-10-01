import sys, time, os
LOG = '/tmp/trueintent_ebpf_stream.log'
sys.stderr.write("[SYSTEM] TrueIntent eBPF engine listening on libssl.so...\n")
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
