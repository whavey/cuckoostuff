#!/bin/sh

venv_path = "/home/cuckoo/sandbox/bin"

cuckoo rooter &
echo $! >> PID_store
gnome-terminal --window-with-profile=hold -e "$venv_path/python2.7 $venv_path/cuckoo -d"
gnome-terminal --window-with-profile=hold -e "$venv_path/python2.7 /home/cuckoo/sandbox/mitre-cuckoo/yara/send2cuckoo.py"
/home/cuckoo/sandbox/mitre-cuckoo/yara/watch.sh
