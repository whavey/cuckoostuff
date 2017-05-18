#!/bin/bash

# This software was produced for the U. S. Government
# under Contract No. W15P7T-12-C-F600, and is
# subject to the Rights in Noncommercial Computer Software
# and Noncommercial Computer Software Documentation
# Clause 252.227-7014 (JUN 1995)
#
# Copyright 2012 The MITRE Corporation. All Rights Reserved.
#
# Author: Michael McFail, MITRE
# September 2012

# This script reads in a list of pids from a file.
# For each pid kill any child processes it may have, and then kill the proccesses itself.
# After processing the pid file is deleted.
#
# This is meant to be paired with the scripts that run iwatch and multiple yara instances,
# but it is written in a general purpose way.

# File which contains process ids to be killed
pid_file=/home/cuckoo/mitre-cuckoo/yara/PID_store

if [ -e "$pid_file" ] # make sure the pid file exists
then
  cat $pid_file | while read ppid
  do
    if [ -n "$ppid" ] # make sure the pid file is not empty
    then
      # list all the children for this process and kill them
      for child in `ps -ef | awk '$3 == '$ppid' { print $2 }'`
      do
        kill $child
      done
      kill $ppid
    fi
  done

  rm $pid_file
fi

