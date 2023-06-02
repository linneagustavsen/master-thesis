#!/bin/bash
interval=10
start="2023-03-17 11:00:00"
stop="2023-03-17 13:00:00"
attackDate="17.03.23"
for systemId in  "teknobyen-gw1" "trd-gw" "ifi2-gw5"
do

    python3 Attack0803RunPacketSizeDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunPacketSizeDetectionTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    
done