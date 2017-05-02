#!/bin/sh

for p in $(find /home/cuckoo/rules/ -type f -name "*.yar"); do yara -w $p $1;done
