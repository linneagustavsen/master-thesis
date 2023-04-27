#!/bin/bash
exec python3 NetFlow/TopKFlows/topkflowDetection.py &
exec python3 NetFlow/Threshold/BytesDetection.py &
exec python3 NetFlow/Threshold/ICMPDetection.py & 
exec python3 NetFlow/Threshold/ICMPDstUnreachableDetection.py & 
exec python3 NetFlow/Threshold/PacketsDetection.py &
exec python3 NetFlow/Threshold/SYNDetection.py &
exec python3 NetFlow/RandomForest/RandomForestDetection.py &
exec python3 NetFlow/RandomForest/RandomForestDetectionCombined.py &
exec python3 NetFlow/RandomForest/RandomForestDetectionNoIP.py &
exec python3 NetFlow/RandomForest/RandomForestDetectionCombinedNoIP.py &
exec python3 NetFlow/RandomForest/RandomForestDetectionEntropy.py &
exec python3 NetFlow/Kmeans/DetectionKmeans.py &
exec python3 NetFlow/Kmeans/DetectionKmeansCombined.py &
exec python3 NetFlow/Kmeans/DetectionKmeansEntropy.py &
exec python3 NetFlow/Entropy/DstDetection.py &
exec python3 NetFlow/Entropy/FlowDetection.py &
exec python3 NetFlow/Entropy/PacketSizeDetection.py &
exec python3 NetFlow/Entropy/SrcDetection.py &
exec python3 NetFlow/Entropy/SYNEntropyDetection.py 