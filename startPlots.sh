#!/bin/bash
python3 runThresholdGeneration.py
python3 mainTelemetry23.py

python3 findMaxMinEntropy.py

python3 NetFlow/TopKFlows/Plotting/plotTopKFlows.py

python3 NetFlow/RandomForest/Plotting/plotRFCombined.py
python3 NetFlow/RandomForest/Plotting/plotRFEntropy.py
python3 NetFlow/RandomForest/Plotting/plotRFFields.py
python3 NetFlow/RandomForest/Plotting/plotRFFieldsNoIP.py

python3 NetFlow/Entropy/FindGoodThresholdRocScores.py