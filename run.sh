#!/bin/bash
# In case of missing tun0 interface, the command for creating the network interface can be found at things_done.txt

cargo b --release # Build the program
ext=$? # Result of build
if [[ $ext -ne 0 ]]; then 
	exit $ext # If build fails, exit 
fi
sudo setcap cap_net_admin=eip target/release/packet_parser # Set the program's capability (so that the program doesn't need to be run as sudo)
target/release/packet_parser & # Start the program as a bg process
pid=$! # Get the bg program's pid
sudo ip addr add 192.168.0.1/24 dev tun0 # Add the ip address to the tun0 network interface
sudo ip link set up dev tun0 # Activate (bring UP) the tun0
trap "kill $pid" INT TERM # Run "kill $pid" when the script receives a INT or TERM signal
wait $pid # Wait until the program has been killed and then end script