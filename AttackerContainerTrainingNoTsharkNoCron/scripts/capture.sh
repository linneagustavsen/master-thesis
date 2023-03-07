#!/bin/bash
#Import variables from file
source variables.sh

DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

for i in {1..300}
do
    file_name="/home/wiresharkTraces/Trace"
    current_time=$(date "+%Y.%m.%d-%H.%M.%S")
    suffix="pcap"
    new_fileName=$file_name.$current_time.$suffix
    #Start Wireshark capture
    tshark -i $interface -w "$new_fileName" -F pcap & pid_tshark=$!
    #Wait for next attack
    sleep 15
    #Stop the Wireshark capture
    kill $pid_tshark
done
