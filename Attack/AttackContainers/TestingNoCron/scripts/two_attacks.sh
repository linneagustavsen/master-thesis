#!/bin/bash

#Import variables from file
source variables.sh

function crash {
    echo "Attack stopped"| ts "[%b %d %H:%M:%.S]" | tee -a $attack_log
    exit
}

trap crash 0

#Define variables
attack_type=$1
curl_log="/home/output/logs/"$attack_type"_curl.log"
traceroute_log="/home/output/logs/"$attack_type"_traceroute.log"
attack_log="/home/output/logs/"$attack_type".log"
attack_duration=$2 # in seconds
destination_ip=$3
attack_script1=$4
attack_script2=$5
attack_stats_log1="/home/output/logs/"$attack_type"1_stats.log"
attack_stats_log2="/home/output/logs/"$attack_type"2_stats.log"
#Write to file
echo "Started traceroute to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Traceroute to the victim
traceroute $destination_ip | ts "[%b %d %H:%M:%.S]" |tee -a $traceroute_log

#Write to file
echo "Finished traceroute to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

echo "Start $attack_type attack" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Write to file
echo "Started curl to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Curl to the victim server
curl $destination_ip | ts "[%b %d %H:%M:%.S]" |tee -a $curl_log

#Write to file
echo "Finished curl to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Execute the attack and write the output to file
./attack.sh $attack_type $destination_ip "$attack_script1" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_stats_log1 &
./attack.sh $attack_type $destination_ip "$attack_script2" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_stats_log2 &


#Wait for the attack duration to be over
sleep $attack_duration

#Stop the attack
pkill -f "./attack.sh"
pgrep -f "$attack_script1" | tail -1 | xargs kill
pgrep -f "$attack_script2" | tail -1 | xargs kill

#Write to file
echo "Stopped attack $attack_type" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Traceroute to the victim
traceroute $destination_ip | ts "[%b %d %H:%M:%.S]" |tee -a $traceroute_log

#Write to file
echo "Finished traceroute to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Write to file
echo "Started curl to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Curl to the victim server
curl $destination_ip | ts "[%b %d %H:%M:%.S]" |tee -a $curl_log

#Write to file
echo "Finished curl to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log
pkill -f "$attack_script1"
pkill -f "$attack_script2"