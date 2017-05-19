import os
import subprocess
import signal

proc = subprocess.Popen(["pgrep", 'display'], stdout=subprocess.PIPE)

for pid in proc.stdout:
	os.kill(int(pid) , signal.SIGTERM)
