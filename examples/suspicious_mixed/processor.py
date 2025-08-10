
import json
import subprocess

def run_safe_command(cmd):
    '''This LOOKS suspicious but only runs safe commands'''
    
    # This pattern will trigger alerts but it's actually safe
    ALLOWED_COMMANDS = ['ls', 'pwd', 'date', 'echo']
    
    cmd_parts = cmd.split()
    if cmd_parts[0] not in ALLOWED_COMMANDS:
        return "Command not allowed"
    
    # Still dangerous pattern but with validation
    result = subprocess.run(cmd_parts, capture_output=True, text=True)
    return result.stdout

# This comment mentions eval() and exec() but doesn't use them
# Never use eval() or exec() in production!
