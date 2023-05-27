#!/bin/bash
python3 NetFlow/Entropy/Plotting/plotEntropyCalculation.py
python3 NetFlow/Entropy/Plotting/plotEntropyCalculationJustAttackPeriod.py
python3 NetFlow/Entropy/Plotting/plotSYNEntropyCalculation.py
python3 NetFlow/Entropy/Plotting/plotSYNEntropyCalculationJustAttack.py

python3 NetFlow/Kmeans/Plotting/plotKmeansCombined.py
python3 NetFlow/Kmeans/Plotting/plotKmeansEntropy.py
python3 NetFlow/Kmeans/Plotting/plotKmeansFields.py

python3 NetFlow/Threshold/Plotting/plotICMPDstUnreachable.py
python3 NetFlow/Threshold/Plotting/plotICMPDstUnreachableJustAttack.py
python3 NetFlow/Threshold/Plotting/plotSYN.py
python3 NetFlow/Threshold/Plotting/plotXmas.py

python3 Telemetry/Entropy/Plotting/plotEntropyCalculation.py
python3 Telemetry/Entropy/Plotting/plotEntropyCalculationJustAttack.py

python3 Telemetry/Kmeans/Plotting/plotKmeansFields.py

python3 Telemetry/Threshold/Plotting/PlotDeviationScoreFromAttack.py
python3 Telemetry/Threshold/Plotting/PlotDeviationScoreFromAttackJustAttack.py

python3 findMinMaxMetricCalc.py

python3 NetFlow/Entropy/FindGoodThresholdEntropy.py
python3 NetFlow/Threshold/FindGoodThresholdSYN.py
python3 Telemetry/Entropy/FindGoodThresholdEntropy.py
python3 Telemetry/Threshold/FindGoodThresholdStatisticalModel.py
