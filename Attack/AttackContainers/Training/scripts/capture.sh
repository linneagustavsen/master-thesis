#!/bin/bash
#Import variables from file
source variables.sh

for i in {1..300}
do
    file_name="/home/wiresharkTraces/Trace"
    current_time=$(date "+%Y.%m.%d-%H.%M.%S")
    suffix="pcap"
    new_fileName=$file_name.$current_time.$suffix
    #Start Wireshark capture
    tshark -i $interface -f "host 128.39.65.26" -w "$new_fileName" -F pcap & pid_tshark=$!
    #Wait for next attack
    sleep 60
    #Stop the Wireshark capture
    kill $pid_tshark
done
