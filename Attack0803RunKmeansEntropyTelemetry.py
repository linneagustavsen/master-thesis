from datetime import timedelta
import sys
from Telemetry.Kmeans.DetectionFromFile.DetectionEntropy import detectionKmeansEntropyTelemetry

# Access the command-line arguments
arguments = sys.argv

# Print the arguments
#print("Number of arguments:", len(arguments))
print("Argument values:", arguments)

start = arguments[1]
stop = arguments[2]
frequency = timedelta(minutes = 1)
attackDate= arguments[3]

detectionKmeansEntropyTelemetry(start, stop, arguments[4], timedelta(minutes=int(arguments[5])), 0.5, 0, 0, attackDate)