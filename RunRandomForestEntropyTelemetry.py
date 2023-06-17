from datetime import timedelta
import sys
from GetWeight import getWeight

from Telemetry.RandomForest.DetectionFromFile.DetectionRFEntropy import detectionRandomForestEntropyTelemetry

# Access the command-line arguments
arguments = sys.argv

# Print the arguments
#print("Number of arguments:", len(arguments))
print("Argument values:", arguments)

start = arguments[1]
stop = arguments[2]
frequency = timedelta(minutes = 1)
attackDate= arguments[3]

weight = getWeight("Entropy", arguments[4], timedelta(minutes=int(arguments[5])), "RandomForest", "Telemetry", attackDate)


detectionRandomForestEntropyTelemetry(start, stop, arguments[4], timedelta(minutes=int(arguments[5])), weight, attackDate)