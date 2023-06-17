#!/bin/bash
interval=5
start="2023-03-24 14:00:00"
stop="2023-03-24 18:00:00"

attackDate="24.03.23"
python3 runAggregation.py "24.03.23" &
python3 runCorrelationAttackType.py 20 "24.03.23" &
python3 runCorrelationDistribution.py "24.03.23" &
python3 runRanking.py "24.03.23" &
for systemId in "tromso-gw5" "teknobyen-gw1" "hoytek-gw2" "bergen-gw3" "trd-gw" "ifi2-gw5"
do
    python3 RunBytesDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunBytesDetectionTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunDstDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunFlowDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunICMPDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunICMPdstUnreachableDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunKmeansCombined.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunKmeansCombinedTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunKmeansEntropy.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunKmeansEntropyTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunKmeansFields.py "$start" "$stop" $attackDate $systemId &
    python3 RunKmeansFieldsTelemetry.py "$start" "$stop" $attackDate $systemId &
    for field in "egress_queue_info__0__cur_buffer_occupancy" "egress_stats__if_1sec_pkts" "egress_stats__if_1sec_octets" "ingress_stats__if_1sec_pkts" "ingress_stats__if_1sec_octets";
    do
        python3 RunStatisticalMethodDetection.py "$start" "$stop" $attackDate $systemId $field &
        python3 RunMaxVarStatisticalMethodDetection.py "$start" "$stop" $attackDate $systemId $field &
    done
    python3 RunPacketsDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunPacketsDetectionTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunPacketSizeDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunPacketSizeDetectionTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestCombined.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestCombinedNoIP.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestCombinedTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestEntropy.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestEntropyTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestFields.py "$start" "$stop" $attackDate $systemId &
    python3 RunRandomForestFieldsNoIP.py "$start" "$stop" $attackDate $systemId &
    python3 RunRandomForestFieldsTelemetry.py "$start" "$stop" $attackDate $systemId &
    python3 RunSrcDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunSYNDetection.py "$start" "$stop" $attackDate $systemId &
    python3 RunSYNEntropyDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunTopKFlows.py "$start" "$stop" $attackDate $systemId &
    python3 RunXmasDetection.py "$start" "$stop" $attackDate $systemId &
    sleep $((30))
done
sleep $((60*60))
python3 WriteCorrelationsToFiles.py
sleep $((60*60))
python3 WriteCorrelationsToFiles.py
sleep $((60*60))
python3 WriteCorrelationsToFiles.py
sleep $((60*60))
python3 WriteCorrelationsToFiles.py
sleep $((5*60))
python3 WriteCorrelationsToFiles.py
pkill python
mv Detections2403 Detections2403_5min_F1
mv HelperFunctions/SimulateRealTimeCP.py HelperFunctions/SimulateRealTime.py

interval=10
start="2023-03-24 14:00:00"
stop="2023-03-24 18:00:00"

attackDate="24.03.23"
python3 runAggregation.py "24.03.23" &
python3 runCorrelationAttackType.py 10 "24.03.23" &
python3 runCorrelationDistribution.py "24.03.23" &
python3 runRanking.py "24.03.23" &
for systemId in "tromso-gw5" "teknobyen-gw1" "hoytek-gw2" "bergen-gw3" "trd-gw" "ifi2-gw5"
do
    python3 RunBytesDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunBytesDetectionTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunDstDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunFlowDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunICMPDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunICMPdstUnreachableDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunKmeansCombined.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunKmeansCombinedTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunKmeansEntropy.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunKmeansEntropyTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunKmeansFields.py "$start" "$stop" $attackDate $systemId &
    python3 RunKmeansFieldsTelemetry.py "$start" "$stop" $attackDate $systemId &
    for field in "egress_queue_info__0__cur_buffer_occupancy" "egress_stats__if_1sec_pkts" "egress_stats__if_1sec_octets" "ingress_stats__if_1sec_pkts" "ingress_stats__if_1sec_octets";
    do
        python3 RunStatisticalMethodDetection.py "$start" "$stop" $attackDate $systemId $field &
        python3 RunMaxVarStatisticalMethodDetection.py "$start" "$stop" $attackDate $systemId $field &
    done
    python3 RunPacketsDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunPacketsDetectionTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunPacketSizeDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunPacketSizeDetectionTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestCombined.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestCombinedNoIP.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestCombinedTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestEntropy.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestEntropyTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestFields.py "$start" "$stop" $attackDate $systemId &
    python3 RunRandomForestFieldsNoIP.py "$start" "$stop" $attackDate $systemId &
    python3 RunRandomForestFieldsTelemetry.py "$start" "$stop" $attackDate $systemId &
    python3 RunSrcDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunSYNDetection.py "$start" "$stop" $attackDate $systemId &
    python3 RunSYNEntropyDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunTopKFlows.py "$start" "$stop" $attackDate $systemId &
    python3 RunXmasDetection.py "$start" "$stop" $attackDate $systemId &
    sleep $((30))
done
sleep $((60*60))
python3 WriteCorrelationsToFiles.py
sleep $((60*60))
python3 WriteCorrelationsToFiles.py
sleep $((60*60))
python3 WriteCorrelationsToFiles.py
sleep $((60*60))
python3 WriteCorrelationsToFiles.py
sleep $((5*60))
python3 WriteCorrelationsToFiles.py
pkill python
mv Detections2403 Detections2403_10min_F1
mv HelperFunctions/SimulateRealTimeCP2.py HelperFunctions/SimulateRealTime.py
sleep $((10*60))

interval=15
start="2023-03-24 14:00:00"
stop="2023-03-24 18:00:00"

attackDate="24.03.23"
python3 runAggregation.py "24.03.23" &
python3 runCorrelationAttackType.py 5 "24.03.23" &
python3 runCorrelationDistribution.py "24.03.23" &
python3 runRanking.py "24.03.23" &
for systemId in "tromso-gw5" "teknobyen-gw1" "hoytek-gw2" "bergen-gw3" "trd-gw" "ifi2-gw5"
do
    python3 RunBytesDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunBytesDetectionTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunDstDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunFlowDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunICMPDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunICMPdstUnreachableDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunKmeansCombined.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunKmeansCombinedTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunKmeansEntropy.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunKmeansEntropyTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunKmeansFields.py "$start" "$stop" $attackDate $systemId &
    python3 RunKmeansFieldsTelemetry.py "$start" "$stop" $attackDate $systemId &
    for field in "egress_queue_info__0__cur_buffer_occupancy" "egress_stats__if_1sec_pkts" "egress_stats__if_1sec_octets" "ingress_stats__if_1sec_pkts" "ingress_stats__if_1sec_octets";
    do
        python3 RunStatisticalMethodDetection.py "$start" "$stop" $attackDate $systemId $field &
        python3 RunMaxVarStatisticalMethodDetection.py "$start" "$stop" $attackDate $systemId $field &
    done
    python3 RunPacketsDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunPacketsDetectionTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunPacketSizeDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunPacketSizeDetectionTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestCombined.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestCombinedNoIP.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestCombinedTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestEntropy.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestEntropyTelemetry.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunRandomForestFields.py "$start" "$stop" $attackDate $systemId &
    python3 RunRandomForestFieldsNoIP.py "$start" "$stop" $attackDate $systemId &
    python3 RunRandomForestFieldsTelemetry.py "$start" "$stop" $attackDate $systemId &
    python3 RunSrcDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunSYNDetection.py "$start" "$stop" $attackDate $systemId &
    python3 RunSYNEntropyDetection.py "$start" "$stop" $attackDate $systemId $interval &
    python3 RunTopKFlows.py "$start" "$stop" $attackDate $systemId &
    python3 RunXmasDetection.py "$start" "$stop" $attackDate $systemId &
    sleep $((30))
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
pkill python
mv Detections2403 Detections2403_15min_F1