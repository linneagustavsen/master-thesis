#!/bin/bash

#Import variables from file
source variables.sh

#Define variables
attack_type=$1
curl_log="/home/output/logs/"$attack_type"_curl.log"
traceroute_log="/home/output/logs/"$attack_type"_traceroute.log"
attack_stats_log="/home/output/logs/"$attack_type"_stats.log"
attack_log="/home/output/logs/"$attack_type".log"
attack_duration=$2 # in seconds
destination_ip=$3
attack_script=$4

#Write to file
echo "Started traceroute to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Traceroute to the victim
traceroute $destination_ip | ts "[%b %d %H:%M:%.S]" |tee -a $traceroute_log

#Write to file
echo "Finished traceroute to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Write to file
echo "Started curl to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Curl to the victim server
curl $destination_ip | ts "[%b %d %H:%M:%.S]" |tee -a $curl_log &

echo "Start $attack_type attack" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Execute the attack and write the output to file
./attack.sh $attack_type $destination_ip "$attack_script" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_stats_log &

#Wait for the attack duration to be over
sleep $attack_duration

#Stop the attack
pkill -f "./attack.sh"
pgrep -f "$attack_script" | tail -1 | xargs kill


#Write to file
echo "Stopped attack $attack_type" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Traceroute to the victim
traceroute $destination_ip | ts "[%b %d %H:%M:%.S]" |tee -a $traceroute_log

#Write to file
echo "Finished traceroute to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Write to file
echo "Started curl to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Curl to the victim server
curl $destination_ip | ts "[%b %d %H:%M:%.S]" |tee -a $curl_log &

pkill -f "$attack_script"