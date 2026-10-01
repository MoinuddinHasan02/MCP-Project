
import re



path = "/home/moinuddin/mcp-tls-guard/demo-ips/agent_cloud.py"

with open(path, "r") as f: content = f.read()



# Locate the broken copy-pasted loop and replace it safely

pattern = re.compile(r"(\s*# --- Replacement loop ---.*?|CANDIDATE_MODELS = \[.*?)sys\.exit\(1\)", re.DOTALL)



clean_code = """    # --- Clean Override ---

    try:

        response = client.models.generate_content(

            model="gemini-flash-latest",

            contents=prompt

        )

    except Exception as e:

        print(f"[-] Server Error: {e}")

        import sys

        sys.exit(1)"""



if pattern.search(content):

    new_content = pattern.sub(clean_code, content)

    with open(path, "w") as f: f.write(new_content)

    print("\n[+] File successfully overridden and formatting fixed!")

else:

    print("\n[!] Could not locate the broken block.")

