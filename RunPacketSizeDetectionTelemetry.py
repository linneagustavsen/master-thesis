from datetime import timedelta
from GetThreshold import getThreshold
from GetWeight import getWeight

from Telemetry.Entropy.DetectionFromFile.Detection import detectionEntropyTelemetry
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
thresholdEntropy_ingress = getThreshold("entropy_packet_size_ingress", systemId, interval, "Entropy", "Telemetry", attackDate)
thresholdEntropyRate_ingress = getThreshold("entropy_rate_packet_size_ingress", systemId, interval, "Entropy", "Telemetry", attackDate)
thresholdEntropy_egress = getThreshold("entropy_packet_size_egress", systemId, interval, "Entropy", "Telemetry", attackDate)
thresholdEntropyRate_egress = getThreshold("entropy_rate_packet_size_egress", systemId, interval, "Entropy", "Telemetry", attackDate)

weightEntropy_ingress = getWeight("entropy_packet_size_ingress", systemId, interval, "Entropy", "Telemetry", attackDate)
weightEntropyRate_ingress = getWeight("entropy_rate_packet_size_ingress", systemId, interval, "Entropy", "Telemetry", attackDate)
weightEntropy_egress = getWeight("entropy_packet_size_egress", systemId, interval, "Entropy", "Telemetry", attackDate)
weightEntropyRate_egress = getWeight("entropy_rate_packet_size_egress", systemId, interval, "Entropy", "Telemetry", attackDate)

detectionEntropyTelemetry(start, stop, systemId,frequency, interval, 10, thresholdEntropy_ingress, thresholdEntropyRate_ingress,  thresholdEntropy_egress, thresholdEntropyRate_egress, weightEntropy_ingress,weightEntropyRate_ingress, weightEntropy_egress, weightEntropyRate_egress, attackDate)
