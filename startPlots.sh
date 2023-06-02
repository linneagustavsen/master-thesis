#!/bin/bash
python3 mainTelemetry23.py

python3 Telemetry/Entropy/Plotting/plotEntropyCalculation.py
python3 Telemetry/Entropy/Plotting/plotEntropyCalculationJustAttack.py
python3 NetFlow/Entropy/Plotting/plotEntropyCalculation.py
python3 NetFlow/Entropy/Plotting/plotEntropyCalculationJustAttack.py

python3 NetFlow/Entropy/FindGoodThresholdEntropy.py
python3 NetFlow/Entropy/FindGoodThresholdSYNEntropy.py
python3 NetFlow/Threshold/FindGoodThreshold.py
python3 NetFlow/TopKFlows/FindGoodThreshold.py
python3 Telemetry/Threshold/FindGoodThresholdStatisticalModel.py

python3 FindGoodThresholdFromFile.py
python3 FindGoodThresholdFromFileWriteToCSV.py

python3 PlotROCcurve.py