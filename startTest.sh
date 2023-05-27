#!/bin/bash
interval=5
for systemId in "teknobyen-gw2" "ma2-gw" "bergen-gw3" "narvik-kv-gw" "trd-gw" "ifi2-gw5" "oslo-gw1"
do
    python3 Attack0803RunBytesDetection.py $systemId $interval
    python3 Attack0803RunBytesDetectionTelemetry.py $systemId $interval
    python3 Attack0803RunDstDetection.py $systemId $interval
    python3 Attack0803RunFlowDetection.py $systemId $interval
    python3 Attack0803RunICMPDetection.py $systemId $interval
    python3 Attack0803RunICMPdstUnreachableDetection.py $systemId $interval
    python3 Attack0803RunKmeansCombined.py $systemId $interval
    python3 Attack0803RunKmeansCombinedTelemetry.py $systemId $interval
    python3 Attack0803RunKmeansEntropy.py $systemId $interval
    python3 Attack0803RunKmeansEntropyTelemetry.py $systemId $interval
    python3 Attack0803RunKmeansFields.py $systemId 
    python3 Attack0803RunKmeansFieldsTelemetry.py $systemId 
    for field in "egress_queue_info__0__cur_buffer_occupancy" "egress_stats__if_1sec_pkts" "egress_stats__if_1sec_octets" "ingress_stats__if_1sec_pkts" "ingress_stats__if_1sec_octets";
    do
        python3 Attack0803RunStatisticalMethodDetection.py $systemId $field 
        python3 Attack0803RunMaxVarStatisticalMethodDetection.py $systemId $field 
    done
    python3 Attack0803RunPacketsDetection.py $systemId $interval
    python3 Attack0803RunPacketsDetectionTelemetry.py $systemId $interval
    python3 Attack0803RunPacketSizeDetection.py $systemId $interval
    python3 Attack0803RunPacketSizeDetectionTelemetry.py $systemId $interval
    python3 Attack0803RunRandomForestCombined.py $systemId $interval
    python3 Attack0803RunRandomForestCombinedNoIP.py $systemId $interval
    python3 Attack0803RunRandomForestCombinedTelemetry.py $systemId $interval
    python3 Attack0803RunRandomForestEntropy.py $systemId $interval
    python3 Attack0803RunRandomForestEntropyTelemetry.py $systemId $interval
    python3 Attack0803RunRandomForestFields.py $systemId 
    python3 Attack0803RunRandomForestFieldsNoIP.py $systemId 
    python3 Attack0803RunRandomForestFieldsTelemetry.py $systemId 
    python3 Attack0803RunSrcDetection.py $systemId $interval
    python3 Attack0803RunSYNDetection.py $systemId 
    python3 Attack0803RunSYNEntropyDetection.py $systemId $interval
    python3 Attack0803RunTopKFlows.py $systemId 
    python3 Attack0803RunXmasDetection.py $systemId 
done

