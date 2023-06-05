#!/bin/bash
interval=5
times=(
    "2023-03-24 14:00:00"
    "2023-03-24 14:15:00"
    "2023-03-24 14:30:00"
    "2023-03-24 14:45:00"
    "2023-03-24 15:00:00"
    "2023-03-24 15:15:00"
    "2023-03-24 15:30:00"
    "2023-03-24 15:45:00"
    "2023-03-24 16:00:00"
    "2023-03-24 16:15:00"
    "2023-03-24 16:30:00"
    "2023-03-24 16:45:00"
    "2023-03-24 17:00:00"
    "2023-03-24 17:15:00"
    "2023-03-24 17:30:00"
    "2023-03-24 17:45:00"
    "2023-03-24 18:00:00"
)
attackDate="24.03.23"
for ((i=0; i< ${#times[@]}-1; i++)); do
    for systemId in "tromso-gw5" "teknobyen-gw1" "hoytek-gw2" "bergen-gw3" "trd-gw" "ifi2-gw5"
    do
        python3 Attack0803RunBytesDetection.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunBytesDetectionTelemetry.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunDstDetection.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunFlowDetection.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunICMPDetection.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunICMPdstUnreachableDetection.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunKmeansCombined.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunKmeansCombinedTelemetry.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunKmeansEntropy.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunKmeansEntropyTelemetry.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunKmeansFields.py "${times[i]}" "${times[i+1]}" $attackDate $systemId &
        python3 Attack0803RunKmeansFieldsTelemetry.py "${times[i]}" "${times[i+1]}" $attackDate $systemId &
        for field in "egress_queue_info__0__cur_buffer_occupancy" "egress_stats__if_1sec_pkts" "egress_stats__if_1sec_octets" "ingress_stats__if_1sec_pkts" "ingress_stats__if_1sec_octets";
        do
            python3 Attack0803RunStatisticalMethodDetection.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $field &
            python3 Attack0803RunMaxVarStatisticalMethodDetection.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $field &
        done
        python3 Attack0803RunPacketsDetection.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunPacketsDetectionTelemetry.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunPacketSizeDetection.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunPacketSizeDetectionTelemetry.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunRandomForestCombined.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunRandomForestCombinedNoIP.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunRandomForestCombinedTelemetry.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunRandomForestEntropy.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunRandomForestEntropyTelemetry.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunRandomForestFields.py "${times[i]}" "${times[i+1]}" $attackDate $systemId &
        python3 Attack0803RunRandomForestFieldsNoIP.py "${times[i]}" "${times[i+1]}" $attackDate $systemId &
        python3 Attack0803RunRandomForestFieldsTelemetry.py "${times[i]}" "${times[i+1]}" $attackDate $systemId &
        python3 Attack0803RunSrcDetection.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunSYNDetection.py "${times[i]}" "${times[i+1]}" $attackDate $systemId &
        python3 Attack0803RunSYNEntropyDetection.py "${times[i]}" "${times[i+1]}" $attackDate $systemId $interval &
        python3 Attack0803RunTopKFlows.py "${times[i]}" "${times[i+1]}" $attackDate $systemId &
        python3 Attack0803RunXmasDetection.py "${times[i]}" "${times[i+1]}" $attackDate $systemId &
        sleep $((15))
    done
    sleep $((13*60))
done