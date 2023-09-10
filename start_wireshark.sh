#!/bin/bash
parent_ip=$(grep -m 1 '^nameserver' /etc/resolv.conf | awk '{print $2}')
export DISPLAY=$parent_ip:0.0
export LIBGL_ALWAYS_INDIRECT=1
nohup wireshark > /dev/null 2>&1 & # Discards the terminal output and doesn't lock the terminal session. 
disown