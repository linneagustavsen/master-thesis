#!/bin/bash

#Import variables from file
source variables.sh

function interupted {
    iptables -D OUTPUT -d ytelse1.uninett.no -p tcp --tcp-flags RST RST -j DROP
}

trap interupted 2
trap interupted 9

#Define variables
attack_type=$1
capture_file=$2
traceroute_log=$3
attack_stats_log=$4
attack_log=$5
attack_duration=$6 # in seconds
destination_ip=$7
destination_port=$8
attack_script=$9


#Traceroute to the victim
traceroute $destination_ip | ts "[%b %d %H:%M:%.S]" |tee -a $traceroute_log

#Write to file
echo "Finished traceroute to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

echo "Start $attack_type attack" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Execute the attack and write the output to file
$attack_script & pid_attack=$!

#Wait for the attack duration to be over
sleep $attack_duration

#Stop the attack
kill $pid_attack

#Write to file
echo "Stopped attack $attack_type" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

#Traceroute to the victim
traceroute $destination_ip | ts "[%b %d %H:%M:%.S]" |tee -a $traceroute_log

#Write to file
echo "Finished traceroute to $destination_ip" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_log