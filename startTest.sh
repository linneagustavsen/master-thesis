#!/bin/bash
interval=10
start="2023-03-08 14:15:00"
stop="2023-03-08 16:00:00"
attackDate="08.03.23"
for systemId in  "teknobyen-gw1" "narvik-gw3" "hovedbygget-gw" "hoytek-gw2" "teknobyen-gw2" "ma2-gw" "bergen-gw3" "narvik-kv-gw" "trd-gw" "ifi2-gw5" "oslo-gw1"
do
    python3 Attack0803RunBytesDetection.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunBytesDetectionTelemetry.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunDstDetection.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunFlowDetection.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunICMPDetection.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunICMPdstUnreachableDetection.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunKmeansCombined.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunKmeansCombinedTelemetry.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunKmeansEntropy.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunKmeansEntropyTelemetry.py "$start" "$stop" $attackDate $systemId $interval 

    python3 Attack0803RunPacketsDetection.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunPacketsDetectionTelemetry.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunPacketSizeDetection.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunPacketSizeDetectionTelemetry.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunRandomForestCombined.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunRandomForestCombinedNoIP.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunRandomForestCombinedTelemetry.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunRandomForestEntropy.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunRandomForestEntropyTelemetry.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunSrcDetection.py "$start" "$stop" $attackDate $systemId $interval 
    python3 Attack0803RunSYNEntropyDetection.py "$start" "$stop" $attackDate $systemId $interval 
    
done

