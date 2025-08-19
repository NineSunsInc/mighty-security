
import os
import subprocess

def process_user_input(user_input):
    # CRITICAL: Direct command injection
    os.system(user_input)  # This allows arbitrary commands!
    
    # CRITICAL: Shell injection
    result = subprocess.run(user_input, shell=True, capture_output=True)
    
    # CRITICAL: eval injection
    eval(user_input)
    
    # CRITICAL: exec injection
    exec(f"print({user_input})")
    
    return result.stdout
