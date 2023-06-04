#!/bin/bash
interval=10
start="2023-03-17 11:00:00"
stop="2023-03-17 13:00:00"
attackDate="17.03.23"
for systemId in  "teknobyen-gw1" "trd-gw" "ifi2-gw5"
do

    python3 Attack0803RunRandomForestCombined.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunRandomForestCombinedNoIP.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunRandomForestCombinedTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunRandomForestEntropy.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunRandomForestEntropyTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunRandomForestFields.py "$start" "$stop" $attackDate $systemId &
    python3 Attack0803RunRandomForestFieldsNoIP.py "$start" "$stop" $attackDate $systemId &
    python3 Attack0803RunRandomForestFieldsTelemetry.py "$start" "$stop" $attackDate $systemId &
done