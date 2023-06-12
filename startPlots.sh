#!/bin/bash
python3 Telemetry/Entropy/FindGoodThresholdEntropy.py

python3 Telemetry/Threshold/FindGoodThresholdStatisticalModel.py

python3 NetFlow/RandomForest/Plotting/plotRFCombined.py
python3 NetFlow/RandomForest/Plotting/plotRFCombinedNoIP.py
python3 NetFlow/RandomForest/Plotting/plotRFFields.py
python3 NetFlow/RandomForest/Plotting/plotRFFieldsNoIP.py

python3 Telemetry/RandomForest/Plotting/plotRFCombined.py
python3 Telemetry/RandomForest/Plotting/plotRFFields.py

python3 NetFlow/Kmeans/Plotting/plotKmeansCombinedOnlyAttackCluster.py
python3 NetFlow/Kmeans/Plotting/plotKmeansFieldsOnlyAttackCluster.py

python3 Telemetry/Entropy/Plotting/plotEntropyCalculationVSNetFlow.py

python3 NetFlow/Entropy/FindGoodThresholdRocScores.py