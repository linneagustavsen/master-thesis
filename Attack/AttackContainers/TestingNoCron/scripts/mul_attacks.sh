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
attack_duration=$2 # in seconds
destination_ip=$3
attack_script1=$4
attack_script2=$5
attack_stats_log1="/home/logs/"$attack_type"1_stats.log"
attack_stats_log2="/home/logs/"$attack_type"2_stats.log"
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
$attack_script1 &> $attack_stats_log1 & pid_attack1=$!
$attack_script2 &> $attack_stats_log2 & pid_attack2=$!

#Wait for the attack duration to be over
sleep $attack_duration

#Stop the attack
kill $pid_attack1
#Stop the attack
kill $pid_attack2

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
