from datetime import timedelta
from GetThreshold import getThreshold

from Telemetry.Threshold.DetectionFromFile.BytesDetection import detectionBytesTelemetry
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
interval = timedelta(minutes=int(arguments[5]))
threshold_ingress = getThreshold("numberOfBytes_ingress", systemId, interval, "Entropy", "Telemetry", attackDate)
threshold_egress = getThreshold("numberOfBytes_egress", systemId, interval, "Entropy", "Telemetry", attackDate)

detectionBytesTelemetry(start, stop, systemId, frequency, interval, 10, threshold_ingress, threshold_egress, attackDate)