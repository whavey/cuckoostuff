rm QUEUE/* HITS/*
./slaughterProcesses.sh
rm hashdb.sqlite
rm log/*
/home/cuckoo/sandbox/bin/python2.7 /home/cuckoo/sandbox/bin/cuckoo clean
