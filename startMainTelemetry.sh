#!/bin/bash
python3 mainTelemetry23.py

python3 findMinMaxMetricCalc.py

python3 Telemetry/Kmeans/Plotting/plotKmeansFields.py
python3 Telemetry/Kmeans/Plotting/plotKmeansEntropy.py
python3 Telemetry/Kmeans/Plotting/plotKmeansCombined.py
