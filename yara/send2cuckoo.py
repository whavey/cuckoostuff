import sys
import time
from subprocess import call

venv_path = "/home/cuckoo/sandbox/bin"

fifo = open(r'/home/cuckoo/sandbox/mitre-cuckoo/yara/cuckoo_pipe','r')
while(True):
	line = fifo.readline()
	if len(line) == 0:
		time.sleep(1)
	else:
		line = line.strip()
		print "running clamav scan on %s:\n" %str(line)
		call(["clamscan", line])
		print "Submitting %s to cuckoo" %str(line)
		call([venv_path+"/python2.7",venv_path+"/cuckoo", "submit", "--memory", "--unique", line])

