import sys
import time
from subprocess import call

fifo = open(r'/home/cuckoo/yara/cuckoo_pipe','r')
while(True):
	line = fifo.readline()
	if len(line) == 0:
		time.sleep(1)
	else:
		line = line.strip()
		print "running clamav scan on %s:\n" %str(line)
		call(["clamscan", line])
		print "Submitting %s to cuckoo" %str(line)
		call(["cuckoo", "submit", "--memory", "--unique", line])

