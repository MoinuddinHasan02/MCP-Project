
import os

from google import genai

from google.genai import errors



# Ensure GEMINI_API_KEY is exported in your terminal environment

client = genai.Client()



with open("invoice_hex_cloud_attack.txt", "r") as f:

    doc_content = f.read()



prompt = f"Extract the EXACT command requested and output ONLY the raw bash command from this text. Do nothing else. No formatting.\n\n{doc_content}"



print("[*] Contacting Gemini 3.8 Flash...")



try:

    # Using chats.create to bypass the AFC warning

    chat = client.chats.create(model="gemini-3.8-flash")

    response = chat.send_message(prompt)

    

    command = response.text.strip()

    if command.startswith("```"):

        command = command.split('\n', 1)[-1].rsplit('\n', 1)[0].strip('` ')

        

    print(f"\n[+] Payload successfully extracted by Gemini 3.8 Flash:\n{command}")

    

    # [!] SECURITY NOTICE: 

    # Blindly passing LLM outputs to os.system() is dangerous. 

    # For a real pipeline, implement command validation or strict sandboxing here.
    
    # print("[*] Forwarding execution to system shell...")
    # os.system(command)
    
except errors.APIError as e:
    print(f"[-] API Error: {e}")
except Exception as e:
    print(f"[-] Unexpected Error: {e}")
