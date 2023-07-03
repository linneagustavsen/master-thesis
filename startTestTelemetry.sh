interval=5
start="2023-03-24 14:00:00"
stop="2023-03-24 18:00:00"

attackDate="24.03.23"
for systemId in "tromso-gw5" "teknobyen-gw1" "hoytek-gw2" "bergen-gw3" "trd-gw" "ifi2-gw5"
do
    python3 RunFlowDetection.py "$start" "$stop" $attackDate $systemId $interval 
   
done
