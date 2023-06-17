from datetime import timedelta
from GetThreshold import getThreshold
from GetWeight import getWeight

from Telemetry.Threshold.DetectionFromFile.Detection import detectionTelemetry
import sys

# Access the command-line arguments
arguments = sys.argv

# Print the arguments
#print("Number of arguments:", len(arguments))
print("Argument values:", arguments)

start = arguments[1]
stop = arguments[2]
frequency = timedelta(minutes = 1)
attackDate= arguments[3]
systemId = arguments[4]
y_field = arguments[5]
threshold = getThreshold(y_field, systemId, 0, "Threshold", "Telemetry", attackDate)
weight = getWeight(y_field, systemId, 0, "Threshold", "Telemetry", attackDate)

detectionTelemetry(start, stop, systemId, y_field, threshold, weight, attackDate)