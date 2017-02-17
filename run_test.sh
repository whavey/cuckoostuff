#!/bin/bash
sudo utils/submit.py $1
sudo ./cuckoo.py
sudo python det-chamber/result_page/result_page.py
exit
