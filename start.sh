#!bin/bash

for systemId in "stangnes-gw" "rodbergvn-gw2" "narvik-gw4" "tromso-fh-gw" "tromso-gw5" "teknobyen-gw1" "narvik-gw3" "hovedbygget-gw" "hoytek-gw2" "teknobyen-gw2" "ma2-gw" "bergen-gw3" "narvik-kv-gw" "trd-gw" "ifi2-gw5" "oslo-gw1"
do
    python3 Attack0803RunBytesDetection.py $systemId 
    python3 Attack0803RunBytesDetectionTelemetry.py $systemId 
    python3 Attack0803RunDstDetection.py $systemId 
    python3 Attack0803RunFlowDetection.py $systemId 
    python3 Attack0803RunICMPDetection.py $systemId 
    python3 Attack0803RunICMPdstUnreachableDetection.py $systemId 
    python3 Attack0803RunKmeansCombined.py $systemId 
    python3 Attack0803RunKmeansCombinedTelemetry.py $systemId 
    python3 Attack0803RunKmeansEntropy.py $systemId 
    python3 Attack0803RunKmeansEntropyTelemetry.py $systemId 
    python3 Attack0803RunKmeansFields.py $systemId 
    python3 Attack0803RunKmeansFieldsTelemetry.py $systemId 
    for field in "egress_queue_info__0__cur_buffer_occupancy" "egress_stats__if_1sec_pkts" "egress_stats__if_1sec_octets" "ingress_stats__if_1sec_pkts" "ingress_stats__if_1sec_octets";
    do
        python3 Attack0803RunStatisticalMethodDetection.py $systemId $field
        python3 Attack0803RunMaxVarStatisticalMethodDetection.py $systemId $field
    done
    python3 Attack0803RunPacketsDetection.py $systemId 
    python3 Attack0803RunPacketsDetectionTelemetry.py $systemId 
    python3 Attack0803RunPacketSizeDetection.py $systemId 
    python3 Attack0803RunRandomForestCombined.py $systemId 
    python3 Attack0803RunRandomForestCombinedNoIP.py $systemId
    python3 Attack0803RunRandomForestCombinedTelemetry.py $systemId 
    python3 Attack0803RunRandomForestEntropy.py $systemId 
    python3 Attack0803RunRandomForestEntropyTelemetry.py $systemId 
    python3 Attack0803RunRandomForestFields.py $systemId 
    python3 Attack0803RunRandomForestFieldsNoIP.py $systemId 
    python3 Attack0803RunRandomForestFieldsTelemetry.py $systemId 
    python3 Attack0803RunSrcDetection.py $systemId 
    python3 Attack0803RunSYNDetection.py $systemId 
    python3 Attack0803RunSYNEntropyDetection.py $systemId 
    python3 Attack0803RunTelemetryPacketSizeDetection.py $systemId 
    python3 Attack0803RunXmasDetection.py $systemId 
    
done

