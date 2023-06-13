#!/bin/bash
interval=15
start="2023-03-24 14:00:00"
stop="2023-03-24 18:00:00"

attackDate="24.03.23"
python3 runAggregation.py "24.03.23" &
python3 runCorrelationAttackType.py "24.03.23" &
python3 runCorrelationDistribution.py "24.03.23" &
python3 runRanking.py "24.03.23" &
for systemId in "tromso-gw5" "teknobyen-gw1" "hoytek-gw2" "bergen-gw3" "trd-gw" "ifi2-gw5"
do
    python3 Attack0803RunBytesDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunBytesDetectionTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunDstDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunFlowDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunICMPDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunICMPdstUnreachableDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunKmeansCombined.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunKmeansCombinedTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunKmeansEntropy.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunKmeansEntropyTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunKmeansFields.py "$start" "$stop" $attackDate $systemId &
    python3 Attack0803RunKmeansFieldsTelemetry.py "$start" "$stop" $attackDate $systemId &
    for field in "egress_queue_info__0__cur_buffer_occupancy" "egress_stats__if_1sec_pkts" "egress_stats__if_1sec_octets" "ingress_stats__if_1sec_pkts" "ingress_stats__if_1sec_octets";
    do
        python3 Attack0803RunStatisticalMethodDetection.py "$start" "$stop" $attackDate $systemId $field &
        python3 Attack0803RunMaxVarStatisticalMethodDetection.py "$start" "$stop" $attackDate $systemId $field &
    done
    python3 Attack0803RunPacketsDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunPacketsDetectionTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunPacketSizeDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunPacketSizeDetectionTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunRandomForestCombined.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunRandomForestCombinedNoIP.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunRandomForestCombinedTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunRandomForestEntropy.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunRandomForestEntropyTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunRandomForestFields.py "$start" "$stop" $attackDate $systemId &
    python3 Attack0803RunRandomForestFieldsNoIP.py "$start" "$stop" $attackDate $systemId &
    python3 Attack0803RunRandomForestFieldsTelemetry.py "$start" "$stop" $attackDate $systemId &
    python3 Attack0803RunSrcDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunSYNDetection.py "$start" "$stop" $attackDate $systemId &
    python3 Attack0803RunSYNEntropyDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 Attack0803RunTopKFlows.py "$start" "$stop" $attackDate $systemId &
    python3 Attack0803RunXmasDetection.py "$start" "$stop" $attackDate $systemId &
    sleep $((60))
done
sleep $((60*60))
python3 WriteCorrelationsToFiles.py
sleep $((60*60))
python3 WriteCorrelationsToFiles.py
sleep $((60*60))
python3 WriteCorrelationsToFiles.py
sleep $((60*60))
python3 WriteCorrelationsToFiles.py
sleep $((10*60))
python3 WriteCorrelationsToFiles.py
sleep $((10*60))
pkill python
mv Detections2403 Detections2403_15min
