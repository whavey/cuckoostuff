#!/usr/local/bin/python
#
# This software was produced for the U. S. Government under
# Contract No. W15P7T-12-C-F600, and is subject to the Rights
# in Noncommercial Computer Software and Noncommercial Computer
# Software Documentation Clause 252.227-7014 (JUN 1995)
#
# Copyright 2012 The MITRE Corporation. All Rights Reserved.
#
# Michael McFail, The MITRE Corporation
#
# July 2012
#    - Initial Version
#
# October 2012
#    - Silently ignore empty files. Previously yara threw an exception.
#    - No longer overwrite existing log files. Append epoch time to the file name and write to log file specified on command line.
#
# 12 November 2012
#    - In the event a log file needs to be moved the date and time are prepended in the form mmddyyyyhhmmss_original_file_name.
#      Previously epoch time had been appended to the file.
#    - Added support to zip up files which matched a signature into an encrypted archive. The 'zip' command is executed as a subprocess
#      and is required to be present on the system.
#    - Support for an error log file added. Defaults to stdout.
#    - Any messages output (to a log file or stdout) are prepended with the date and time in mmddyyyyhhmmss format.
#
# Program to read from a named pipe (fifo). The pipe contains file names which will be sent to multiple threads that each run yara.
# If a yara signature hits the file will be moved to another directory so further analysis can be performed.
# Yara hits may optionally be logged to file (default is stdout). In the event a log file is specified but already exists
# the existing log file will be renamed. The epoch time (GMT) will be appended.
#

import threading
import Queue
import os
import time
import argparse
import subprocess
import yara
import shutil
import hashlib
import sqlite3
from datetime import date

# Database connection

# The FileWriter thread reads from the output queue that the worker threads write to. It prints the output to a file, or stdout. Output is prepended with the current UTC date and time.
class FileWriterThread(threading.Thread):
    def __init__(self, output_queue, file):
        threading.Thread.__init__(self)
        self.output_queue = output_queue
        self.file = file

    def run(self):
        while True:
            output = self.output_queue.get()

            current_gm_time = time.gmtime()

            timestamped_output = str(current_gm_time.tm_mon) + str(current_gm_time.tm_mday) + str(current_gm_time.tm_year) + str(current_gm_time.tm_hour) + str(current_gm_time.tm_min) + str(current_gm_time.tm_sec) + ': ' + output

            if self.file is None:
                print timestamped_output;
            else:
                self.file.write(timestamped_output + "\n")
                self.file.flush()

            self.output_queue.task_done()

# Worker thread calls yara subprocess. If a yara signature hits the file it is moved off to another directory.
class WorkerThread(threading.Thread):
    def __init__(self, inqueue, match_output_queue, error_output_queue, output_dir_name, rules, encryption_password):
        threading.Thread.__init__(self)
        self.inqueue = inqueue
        self.outqueue = match_output_queue
        self.errqueue = error_output_queue
        self.output_dir_name = output_dir_name
        self.rules = rules
        self.encryption_password = encryption_password

    def run(self):

	con = sqlite3.connect("/home/cuckoo/mitre-cuckoo/yara/hashdb.sqlite") 			
	cur = con.cursor() 				
        while True:
            output = ""
            filename = self.inqueue.get()

            try:
                if DEBUG:
                    print "sending " + filename + " to yara.\n"

                # Zero length files cause rules.match() to raise an exception
                # Currently zero length files are silently ignored
                if os.path.getsize(filename) > 0:
                    # See what yara rules this input matches
                    matches = rules.match(filename);

                    # If there are matches copy the file to the output directory and write out the names of the matched rules
                    if len(matches) > 0:
			print "matches in thread {}\n".format(self)
			cur.execute("update hashes set yara=? where name=?",(str(len(matches)),filename))
			con.commit()
                        output = filename + " matched the following yara rules:\n"
                        if DEBUG:
                            print filename + " matched the following yara rules:\n"
                        for m in matches:
                            output += "%s" % m + "\n"
                            if DEBUG:
                                print "%s" % m

                        if encryption_password is not None and encryption_password.strip() != '':
                            (path, basename) = os.path.split(filename)
                            zipped_filename = os.path.join(self.output_dir_name, basename + ".zip")

                            args_array = ["zip", "-j", "-0", "-P", self.encryption_password, zipped_filename, filename]
                            if DEBUG:
                                print "Zipping " + filename + ". Output dir: " + self.output_dir_name
                                print "Command line: " + ' '.join(args_array)

                            # zip (without compression but with encryption) and move
                            retcode = subprocess.call(args_array)
                            if retcode != 0:
                                self.errqueue.put("Call to zip proceess returned error code " + str(retcode));
                        else:
                            # Straight file copy, no zipping or encryption
                            shutil.copy2(filename, self.output_dir_name);
                        self.outqueue.put(output);
                    elif DEBUG:
                        print filename + " did not match any yara rules\n"
            except OSError as e:
                if len(e.args) == 1:
                    output = "OSError({0}): {1}".format(e.errno, e.strerror)
                    if DEBUG:
                       print "OSError({0}): {1}".format(e.errno, e.strerror)
                elif len(e.args) == 2:
                    output = "OSError({0}): {1} {2}".format(e.errno, e.strerror, e.filename)
                    if DEBUG:
                        print "OSError({0}): {1} {2}".format(e.errno, e.strerror, e.filename)

                self.errqueue.put(output)
	    con.close()
            self.inqueue.task_done()

# Given a log file name, check to see if the log file already exists. If it does move the existing log file to a new file name containing the date and time.
# If the file name containing the date and time already exists rename it with '.old' appended first.
def movefileifneeded(log_file_name):
    if len(log_file_name) > 0:
        if os.path.exists(log_file_name):
            (path, base_file_name) = os.path.split(log_file_name)
            if base_file_name is None or base_file_name.strip() == '':
                print "Error: can't write log to " + path + ". It is a directory."
                exit(1)

            # If the log file exists append the epoch time to it so it's not overwritten
            # Make sure the file we're creating doesn't exist as well (unlikely, but possible)
            current_gm_time = time.gmtime()

            new_base_file_name = str(current_gm_time.tm_mon) + str(current_gm_time.tm_mday) + str(current_gm_time.tm_year) + str(current_gm_time.tm_hour) + str(current_gm_time.tm_min) + str(current_gm_time.tm_sec) + '_' + base_file_name

            new_log_file_name = os.path.join(path, new_base_file_name)

            # If the log file name that we're moving to (with UTC time prepended) already exists, add a ".old" to the end so we don't overwrite it
            if os.path.exists(new_log_file_name):
                shutil.move(new_log_file_name, new_log_file_name+".old")

            if DEBUG:
                print "Moving existing log file " + log_file_name + " to " + new_log_file_name

            shutil.move(log_file_name, new_log_file_name)

#
# Parse command line args. Start up one thread to write to the log file.
# Start up yara threads to do the actual processessing.
# Loop forever and read file names off the FIFO; distribute them to the yara threads.
#
if __name__ == '__main__':

    #the default number of concurrent yara threads to run
    num_threads=4

    #various other variable defuults
    fifo_name = ''
    output_dir_name = ''
    log_file_name = ''
    error_log_file_name = ''

    encryption_password = None

    log_file = None
    error_log_file = None
    rules = None
    filename_queue = None

    match_output_queue = None
    error_output_queue = None
    match_log_file_writer_thread = None
    error_log_file_writer_thread = None

    global DEBUG
    DEBUG = True

    parser = argparse.ArgumentParser(description='Watch a FIFO and run multiple yara processes over files placed into it.')
    parser.add_argument("-s", "--signatures", action="store", dest="sigs", nargs='*', required=True, help="Yara signatures directory or file")
    parser.add_argument("-f", "--fifo", action="store", dest="fifo_name", required=True, help="Fifo to read file names from")
    parser.add_argument("-o", "--output-directory", action="store", dest="output_dir_name", required=True, help="Directory where files with yara hits should be moved")
    parser.add_argument("-l", "--log-file", action="store", dest="log_file_name", help="Log file where yara matches are written. Defaults to stdout. If the file already exists it will be renamed with UTC time.")
    parser.add_argument("-n", "--num-threads", action="store", type=int, dest="num_threads", help="Number of worker threads. Default: 4")
    parser.add_argument("-z", "--zip", action="store", dest="encryption_password", help="Zip up matching files and encrypt using the specified password. Zipping is done without compression.")
    parser.add_argument("-e", "--error-log-file", action="store", dest="error_log_file_name", help="Log file where errors are written. Defaults to stdout. If the file already exists it will be renamed with the UTC time.")
    parser.add_argument("-d", "--debug", action="store_true", dest="debug", help="Print debug messages")
    args = parser.parse_args()

    if args.debug:
        DEBUG = True
        print "debugging enabled"
    
    def recurse_dir(rulesdict,sig): 		
	# if the user specified a single signature file then compile rules from it
	if os.path.isfile(sig):
		rulesdict[sig]=sig 
	# otherwise if they specified a directory try to treat all the files within it as signature files
	elif os.path.isdir(sig):
		for entry in os.listdir(sig):
			# create the absolute path to the file
			entry = os.path.join(sig,entry)
			recurse_dir(rulesdict,entry)
	return rulesdict

    if args.sigs:
    	rulesdict = {}
	for sig in args.sigs:
		r = recurse_dir(rulesdict,sig)	
	rules = yara.compile(filepaths=r)
    else:
        print "Error: At least one yara signature file or directory is requred."
        exit(1)

    if args.fifo_name:
        fifo_name = args.fifo_name
    else:
        print "Error: Input fifo is required."
        exit(1)

    if args.num_threads:
        num_threads = args.num_threads

    if args.output_dir_name:
        output_dir_name = args.output_dir_name
    else:
        print "Error: Output directory is required."
        exit(1)

    if args.encryption_password:
        encryption_password = args.encryption_password

    #This isn't required. It defaults to stdout
    if args.log_file_name:
        log_file_name = args.log_file_name


    #This isn't required. It defaults to stdout.
    if args.error_log_file_name:
        error_log_file_name = args.error_log_file_name
    # Queue where the main thread puts input directly from the fifo. Each of the worker threads reads from the queue.
    filename_queue = Queue.Queue()

    # Queue where the worker threads log matches from yara. This output goes to a file or stdout
    match_output_queue = Queue.Queue()

    # Queue where errors are logged. This output goes to a file or stdout
    error_output_queue = Queue.Queue()

    # Deal with the log file, if specified
    if len(log_file_name) > 0:
        movefileifneeded(log_file_name)

        if DEBUG:
            print "Logging matches to file " + log_file_name + "\n\n"

        log_file = open(log_file_name, 'w')
    # Deal with the error log file, if specified
    if len(error_log_file_name) > 0:
        movefileifneeded(error_log_file_name)

        if DEBUG:
            print "Logging errors to file " + error_log_file_name + "\n\n"

        error_log_file = open(error_log_file_name, 'w')

    if os.path.exists(fifo_name):
        fifo = open(fifo_name, 'r')
    else:
        print "Error: '" + fifo_name + "' is not a valid file for the FIFO queue. The pipe must exist (use linux mkfifo command)."
        exit(1)

    # Start the thread to read from output_queue and write to the match log file
    match_log_file_writer_thread = FileWriterThread(match_output_queue, log_file)
    match_log_file_writer_thread.setDaemon(True)
    match_log_file_writer_thread.start()

    # Start the thread to read from error_output_queue and write to the error log file
    error_log_file_writer_thread = FileWriterThread(error_output_queue, error_log_file)
    error_log_file_writer_thread.setDaemon(True)
    error_log_file_writer_thread.start()

    # Fire up the appropriate number of worker threads
    for i in range(num_threads):
        t = WorkerThread(filename_queue, match_output_queue, error_output_queue, output_dir_name, rules, encryption_password)
        t.setDaemon(True)
        t.start()
    
    def check_hash(md5,name):
	con = sqlite3.connect("hashdb.sqlite") 			
	cur = con.cursor() 				
	try:
		cur.execute('''create table if not exists hashes 
			       (
				scanned date, 
				hash text, 
				name text, 
				yara text,
				classification text
			       )'''
		)
		
		cur.execute("select * from hashes where hash is ?",(str(md5),))	
		hit = cur.fetchall()
		if hit: 							
			print "{} already scanned with a classification of: {}\n\n".format(name,hit[0])
			con.commit()
			con.close()
			return True
		else:							
			cur.execute("insert into hashes (scanned,hash,name,yara,classification) values (?,?,?,?,?)",
				     (date.today(),md5,name,'unk','unk'))
			print "Inserted {} : {} into database\n\n".format(name,md5)
			con.commit()
			con.close()
			return False
	
	except Exception, e:
		print "Exception in Check Hash: {}".format(e)
		pass

    #Loop forever and copy file names from the fifo to the queue
    while True:
        line = fifo.readline()
        
	if len(line)==0:
            # Nothing on the fifo, sleep for one second and then try again
            time.sleep(1)
        
	else:
            line = line.strip()
	    
	    # Open the specified file as binary data, read all bytes into buffer, and generate its md5hash
	    md5 = hashlib.md5(open(line,'rb').read()).hexdigest() 
	    if check_hash(md5,line):
		continue
            
	    if DEBUG:
                print "Processing " + str(line) + "\n"
	    
	    # Skip over directory file, the files within it will still be checked
	    if os.path.isdir(line): 
	    	continue
            
	    filename_queue.put(str(line))

    queue.join()
    pipe.close()
