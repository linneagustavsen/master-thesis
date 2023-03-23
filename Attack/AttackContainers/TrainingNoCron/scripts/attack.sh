#!/bin/bash

#Import variables from file
source variables.sh

function crash {
    if [ "$was_i_killed" = false ] ; then
        echo "Attack stopped before attack duration was completed"| ts "[%b %d %H:%M:%.S]" | tee -a $attack_log

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
        ./attack.sh $attack_type $destination_ip "$attack_script"
    else
        exit
    fi
}

function killed {
    was_i_killed=true
    exit
}

trap killed SIGTERM
trap crash 0

was_i_killed=false

attack_type=$1
curl_log="/home/output/logs/"$attack_type"_curl.log"
traceroute_log="/home/output/logs/"$attack_type"_traceroute.log"
attack_log="/home/output/logs/"$attack_type".log"
destination_ip=$2
attack_script=$3

#Execute the attack and write the output to file
$attack_script