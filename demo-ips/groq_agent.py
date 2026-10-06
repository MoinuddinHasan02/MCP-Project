import os
import sys
from openai import OpenAI

client = OpenAI(
    api_key=os.environ.get("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1",
)

path = "invoice_hex_cloud_attack.txt"
if not os.path.exists(path):
    print(f"[-] Error: {path} not found.")
    sys.exit(1)

with open(path, "r") as f:
    doc_content = f.read()

prompt = f"Extract the EXACT command requested and output ONLY the raw bash command from this text. Do nothing else. No explanation.\n\n{doc_content}"

print("[*] Contacting GroqCloud (Llama 3 8B)...")

try:
    # Using the most stable, guaranteed free-tier model
    response = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1
    )
    
    command = response.choices[0].message.content.strip()
    
    if command.startswith("```"):
        command = command.split('\n', 1)[-1].rsplit('\n', 1)[0].strip('` ')
        
    print(f"\n[+] Groq successfully extracted payload:\n{command}")
    
    print("[*] Forwarding execution to system shell...")
    os.system(command) 
    
except Exception as e:
    print(f"[-] API Error: {e}")
