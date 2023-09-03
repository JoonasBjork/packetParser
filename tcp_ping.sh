#!/bin/bash
sudo hping3 --syn --ack --urg --rst  --data 6 -c 1 -p 555 192.168.0.2