#!bin/bash
exec python3 Telemetry/Threshold/PacketsDetection.py &
exec python3 Telemetry/Threshold/DetectionMaxVar.py & 
exec python3 Telemetry/Threshold/BytesDetection.py &
exec python3 Telemetry/RandomForest/DetectionRF.py &
exec python3 Telemetry/Kmeans/Detection.py &
exec python3 Telemetry/Kmeans/DetectionCombined.py &
exec python3 Telemetry/Kmeans/DetectionEntropy.py &
exec python3 Telemetry/Entropy/Detection.py 