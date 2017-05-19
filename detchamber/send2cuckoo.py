import sys
import time
from subprocess import call,Popen,PIPE

venv_path = "/home/cuckoo/sandbox/bin"

fifo = open(r'/home/cuckoo/sandbox/mitre-cuckoo/yara/cuckoo_pipe','r')
while(True):
	line = fifo.readline()
	if len(line) == 0:
		time.sleep(1)
	else:
		line = line.strip()
		sample = line.split("/")[-1]
		#print "running clamav scan on %s:\n" %str(line)
		#call(["clamscan", line])

		print "Running %s through LaikaBOSS"%sample
		laika = Popen(["/home/cuckoo/laikaboss/laika.py",line],stdout=PIPE)
		jq = Popen(["jq",".scan_result[]"],stdin=laika.stdout,stdout=PIPE)
		laika.stdout.close()
		result,err = jq.communicate()

		print "LaikaBOSS results in laika_results directory"
		rf = open(r'/home/cuckoo/sandbox/mitre-cuckoo/yara/laika_results/%s'%sample,'w')
		print >> rf, result
		rf.close()

#		print "Submitting %s to cuckoo" %sample)

		#call([venv_path+"/python2.7",venv_path+"/cuckoo", "submit", "--memory", "--unique", line])

