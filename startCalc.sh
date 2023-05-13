#!/bin/bash 
{ python3 runThresholdGeneration.py; python3 mainTelemetry.py; python3 NetFlow/Kmeans/Plotting/plotKmeansFields.py; python3 NetFlow/Kmeans/Plotting/plotKmeansEntropy.py; python3 NetFlow/Kmeans/Plotting/plotKmeansCombined.py; } &
