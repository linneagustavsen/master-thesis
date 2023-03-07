#!/bin/bash

#Import variables from file
source variables.sh

#Define variables
attack_type=$1
capture_file=$2
traceroute_log=$3
attack_log=$4
attack_duration=$5 # in seconds
destination_ip=$6
attack_script1=$7
attack_script2=$8


#Traceroute to the victim
traceroute $destination_ip | ts "[%b %d %H:%M:%.S]" |tee -a $traceroute_log

#Write to file
echo "Finished traceroute to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

echo "Start $attack_type attack" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Execute the attack and write the output to file
$attack_script1 & pid_attack1=$!
$attack_script2 & pid_attack2=$!

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
