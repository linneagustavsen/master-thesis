from datetime import timedelta
import sys

from Telemetry.RandomForest.DetectionFromFile.DetectionRFFields import detectionRandomForestTelemetry

# Access the command-line arguments
arguments = sys.argv

# Print the arguments
#print("Number of arguments:", len(arguments))
print("Argument values:", arguments)

start = arguments[1]
stop = arguments[2]
frequency = timedelta(minutes = 1)
attackDate= arguments[3]

detectionRandomForestTelemetry(start, stop, arguments[4], attackDate)