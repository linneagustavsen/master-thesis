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
    tshark -i $interface -f "host 34.105.154.156 or host  18.236.63.8 or host 3.69.241.159 or host 34.254.179.150 or host 13.48.73.156 or host 13.82.53.167 or host 13.79.144.22 or host 35.228.220.215 or host 158.39.1.94 or host 158.39.1.126 or host 158.39.1.98 or host 158.39.1.90" -w "$new_fileName" -F pcap & pid_tshark=$!
    #Wait for next attack
    sleep 15
    #Stop the Wireshark capture
    kill $pid_tshark
done
