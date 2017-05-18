#!/bin/sh

# This software was produced for the U. S. Government
# under Contract No. W15P7T-12-C-F600, and is
# subject to the Rights in Noncommercial Computer Software
# and Noncommercial Computer Software Documentation
# Clause 252.227-7014 (JUN 1995)
#
# Copyright. 2017 The MITRE Corporation. All Rights Reserved.
#
# Author: Michael McFail, MITRE
# September 2012
#
# Updated by: Wayne Havey, MITRE
# March 2017

# This script launches inotify and python processes to do distributed yara processesing. 
# The pids for the two subprocesses are saved off to a PID_store for later cleanup by slaughterprocesses python script.
#
# Yara has implemented threading.
# However it is slower than the distribute_fifo threading implementation for large amounts of files.

path = "/home/cuckoo/sandbox/mitre-cuckoo/yara/"
q = "QUEUE"
h = "HITS"
pid = "PID_store"
dis = "distribute_fifo.py"
mal = "malicious-indicators"
pipe = "pipe"
log = "log/yara.log"

inotifywait -e CREATE,MOVE -mrq $path$q --format "%w%f" > pipe &
inotify_pid0=$!

inotifywait -e CREATE,MOVE -mrq $path$h --format "%w%f" > cuckoo_pipe &
inotify_pid1=$!

echo $inotify_pid0 >> $path$pid
echo $inotify_pid1 >> $path$pid

/home/cuckoo/sandbox/bin/python2.7 $path$dis -d -n 10 -s $path$mal -f $path$pipe -o $path$h -l $path$log &

yara_pid=$!
echo $yara_pid >> $path$pid
