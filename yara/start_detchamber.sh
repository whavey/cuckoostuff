#!/bin/sh
cuckoo rooter &
echo $! >> PID_store
gnome-terminal --window-with-profile=hold -e "cuckoo -d"
gnome-terminal --window-with-profile=hold -e "python2.7 /home/cuckoo/mitre-cuckoo/yara/send2cuckoo.py"
/home/cuckoo/yara/watch.sh
