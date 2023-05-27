#!/bin/bash
interval=10
start="2023-03-08 14:15:00"
stop="2023-03-08 16:00:00"
attackDate="08.03.23"
for systemId in "stangnes-gw" "rodbergvn-gw2" "narvik-gw4" "tromso-fh-gw" "tromso-gw5" "teknobyen-gw1" "narvik-gw3" "hovedbygget-gw" "hoytek-gw2" "teknobyen-gw2" "ma2-gw" "bergen-gw3" "narvik-kv-gw" "trd-gw" "ifi2-gw5" "oslo-gw1"
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
done

