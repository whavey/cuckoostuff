rm QUEUE/* HITS/* 2> /dev/null
./slaughterProcesses.sh
rm hashdb.sqlite 2> /dev/null
rm log/* 2> /dev/null
/home/cuckoo/sandbox/bin/python2.7 /home/cuckoo/sandbox/bin/cuckoo clean
"yes" | rm lex* 2> /dev/null
"yes" | rm yacc* 2> /dev/null
