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

inotifywait -e CREATE,MOVE -mrq /home/cuckoo/yara/QUEUE --format "%w%f" > pipe &
inotify_pid0=$!

inotifywait -e CREATE,MOVE -mrq /home/cuckoo/yara/HITS --format "%w%f" > cuckoo_pipe &
inotify_pid1=$!

echo $inotify_pid0 >> /home/cuckoo/yara/PID_store
echo $inotify_pid1 >> /home/cuckoo/yara/PID_store

python2.7 /home/cuckoo/yara/distribute_fifo.py -d -n 10 -s /home/cuckoo/yara/malicious-indicators/ -f /home/cuckoo/yara/pipe -o /home/cuckoo/yara/HITS -l /home/cuckoo/yara/log/yara.log &

yara_pid=$!
echo $yara_pid >> /home/cuckoo/yara/PID_store
