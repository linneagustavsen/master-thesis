#!bin/bash
exec python3 TopKFlows/topkflow.py &
exec python3 Threshold/BytesDetection.py &
exec python3 Threshold/ICMPDetection.py & 
exec python3 Threshold/ICMPDstUnreachableDetection.py & 
exec python3 Threshold/PacketsDetection.py &
exec python3 Threshold/SYNDetection.py &
exec python3 RandomForest/RandomForestDetection.py &
exec python3 RandomForest/RandomForestDetectionCombined.py &
exec python3 RandomForest/RandomForestDetectionEntropy.py &
exec python3 Kmeans/DetectionKmeans.py &
exec python3 Kmeans/DetectionKmeansCombined.py &
exec python3 Kmeans/DetectionKmeansEntropy.py &
exec python3 Entropy/DstDetection.py &
exec python3 Entropy/FlowDetection.py &
exec python3 Entropy/PacketSizeDetection.py &
exec python3 Entropy/SrcDetection.py &
exec python3 Entropy/SYNEntropyDetection.py 