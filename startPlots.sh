#!/bin/bash
python3 Telemetry/Entropy/Plotting/plotEntropyCalculation.py
python3 Telemetry/Entropy/Plotting/plotEntropyCalculationJustAttack.py
python3 NetFlow/Entropy/Plotting/plotEntropyCalculation.py
python3 NetFlow/Entropy/Plotting/plotEntropyCalculationJustAttack.py

python3 PlotROCcurve.py