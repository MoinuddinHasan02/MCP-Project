
import os

f = os.path.expanduser("~/mcp-tls-guard/module4-semantic/inspector.py")

with open(f, "r") as file: data = file.read()

if "urllib.request" not in data:

    data = "import urllib.request\n" + data

    dash = "        try:\n            urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:5000', data=json.dumps(ev).encode(), headers={'Content-Type': 'application/json'}), timeout=1)\n        except: pass\n        print(json.dumps(ev))"

    data = data.replace("        print(json.dumps(ev))", dash)

    with open(f, "w") as file: file.write(data)

    print("Dashboard connected successfully!")

