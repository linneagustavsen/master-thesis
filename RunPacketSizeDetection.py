from datetime import timedelta
import sys
from GetThreshold import getThreshold
from GetWeight import getWeight
from NetFlow.Entropy.DetectionFromFile.PacketSizeDetection import detectionPS

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
thresholdPSEntropy = getThreshold("packetSizeEntropy", systemId, interval, "Entropy", "NetFlow", attackDate)
thresholdPSEntropyRate = getThreshold("packetSizeEntropyRate", systemId, interval, "Entropy", "NetFlow", attackDate)

weightPSEntropy = getWeight("packetSizeEntropy", systemId, interval, "Entropy", "NetFlow", attackDate)
weightPSEntropyRate = getWeight("packetSizeEntropyRate", systemId, interval, "Entropy", "NetFlow", attackDate)

detectionPS(start, stop, systemId, frequency, interval, 10, thresholdPSEntropy, thresholdPSEntropyRate, weightPSEntropy, weightPSEntropyRate, attackDate)