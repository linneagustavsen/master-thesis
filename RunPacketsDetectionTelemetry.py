from datetime import timedelta
from GetThreshold import getThreshold
from GetWeight import getWeight

from Telemetry.Threshold.DetectionFromFile.PacketsDetection import detectionPacketsTelemetry
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
threshold_ingress = getThreshold("numberOfPackets_ingress", systemId, interval, "Entropy", "Telemetry", attackDate)
threshold_egress = getThreshold("numberOfPackets_egress", systemId, interval, "Entropy", "Telemetry", attackDate)

weight_ingress = getWeight("numberOfPackets_ingress", systemId, interval, "Entropy", "Telemetry", attackDate)
weight_egress = getWeight("numberOfPackets_egress", systemId, interval, "Entropy", "Telemetry", attackDate)

detectionPacketsTelemetry(start, stop, systemId, frequency, interval, 10, threshold_ingress, threshold_egress, weight_ingress, weight_egress, attackDate)