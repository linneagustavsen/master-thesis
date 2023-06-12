#!/bin/bash

python3 Telemetry/Entropy/Plotting/plotEntropyCalculationVSNetFlow.py

python3 NetFlow/Entropy/FindGoodThresholdRocScores.py