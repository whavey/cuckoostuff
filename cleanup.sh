#!/bin/bash
rm det-chamber/files/FinalLog.db
rm arff_test.arff
sudo rm -rf storage/
sudo ./cuckoo.py --clean
exit
