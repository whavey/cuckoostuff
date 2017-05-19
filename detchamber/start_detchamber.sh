#!/bin/sh

path="/home/cuckoo/sandbox/bin"
c="/cuckoo"
$path$c rooter &
echo $! >> PID_store
gnome-terminal --window-with-profile=hold -e "$path/python2.7 $path/cuckoo -d"
gnome-terminal --window-with-profile=hold -e "$path/python2.7 /home/cuckoo/sandbox/mitre-cuckoo/yara/send2cuckoo.py"
/home/cuckoo/sandbox/mitre-cuckoo/yara/watch.sh
