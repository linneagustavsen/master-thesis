interval=5
start="2023-03-24 14:00:00"
stop="2023-03-24 18:00:00"

attackDate="24.03.23"

interval=10
for systemId in "ifi2-gw5"
do
    python3 RunRandomForestCombined.py "$start" "$stop" $attackDate $systemId $interval 
done