#!bin/bash
exec python3 Threshold/PacketsDetection.py &
exec python3 Threshold/DetectionMaxVar.py & 
exec python3 Threshold/BytesDetection.py &
exec python3 RandomForest/DetectionRF.py &
exec python3 Kmeans/Detection.py &
exec python3 Kmeans/DetectionCombined.py &
exec python3 Kmeans/DetectionEntropy.py &
exec python3 Entropy/Detection.py 