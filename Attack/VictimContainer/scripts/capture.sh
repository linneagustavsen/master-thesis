#!/bin/bash
#Import variables from file
source variables.sh

for i in {1..800}
do
    file_name="/home/wiresharkTraces/Trace"
    current_time=$(date "+%Y.%m.%d-%H.%M.%S")
    suffix="pcap"
    new_fileName=$file_name.$current_time.$suffix
    #Start Wireshark capture
    tshark -i $interface -f "host 158.39.1.94 or host 158.39.1.126 or host 158.39.1.98 or host 158.39.1.90" -w "$new_fileName" -F pcap & pid_tshark=$!
    #Wait for next attack
    sleep 15
    #Stop the Wireshark capture
    kill $pid_tshark
done
