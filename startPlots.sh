#!/bin/bash
python3 mainTelemetry23.py

python3 findMaxMinEntropy.py

python3 NetFlow/TopKFlows/Plotting/plotTopKFlows.py

python3 NetFlow/RandomForest/Plotting/plotRFCombined.py
python3 NetFlow/RandomForest/Plotting/plotRFEntropy.py
python3 NetFlow/RandomForest/Plotting/plotRFFields.py
python3 NetFlow/RandomForest/Plotting/plotRFFieldsNoIP.py

python3 Telemetry/RandomForest/Plotting/plotRFCombined.py
python3 Telemetry/RandomForest/Plotting/plotRFEntropy.py
python3 Telemetry/RandomForest/Plotting/plotRFFields.py

python3 Telemetry/Kmeans/Plotting/plotKmeansCombined.py
python3 Telemetry/Kmeans/Plotting/plotKmeansEntropy.py
python3 Telemetry/Kmeans/Plotting/plotKmeansFields.py

python3 NetFlow/Kmeans/Plotting/plotKmeansCombinedOnlyAttackCluster.py
python3 NetFlow/Kmeans/Plotting/plotKmeansEntropyOnlyAttackCluster.py
python3 NetFlow/Kmeans/Plotting/plotKmeansFieldsOnlyAttackCluster.py

python3 NetFlow/Entropy/FindGoodThresholdRocScores.py