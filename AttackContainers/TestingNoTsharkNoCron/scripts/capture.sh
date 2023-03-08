#!/bin/bash
#Import variables from file
source variables.sh

function interupted {
    iptables -D OUTPUT -d ytelse1.uninett.no -p tcp --tcp-flags RST RST -j DROP
}

trap interupted 2
trap interupted 9

DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

for i in {1..300}
do
    file_name="/home/wiresharkTraces/Trace"
    current_time=$(date "+%Y.%m.%d-%H.%M.%S")
    suffix="pcap"
    new_fileName=$file_name.$current_time.$suffix
    #Start Wireshark capture
    tshark -i $interface -f "host 128.39.65.26" -w "$new_fileName" -F pcap & pid_tshark=$!
    #Wait for next attack
    sleep 15
    #Stop the Wireshark capture
    kill $pid_tshark
done
