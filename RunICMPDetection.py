from datetime import timedelta
from GetThreshold import getThreshold
from GetWeight import getWeight

from NetFlow.Threshold.DetectionFromFile.ICMPDetection import detectionICMP
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
thresholdICMPRatio = getThreshold("icmpRatio", systemId, interval, "Entropy", "NetFlow", attackDate)
thresholdNumberOfICMPPackets = getThreshold("icmpPackets", systemId, interval, "Entropy", "NetFlow", attackDate)

weightICMPRatio = getWeight("icmpRatio", systemId, interval, "Entropy", "NetFlow", attackDate)
weightNumberOfICMPPackets = getWeight("icmpPackets", systemId, interval, "Entropy", "NetFlow", attackDate)

detectionICMP(start, stop, systemId, frequency, interval, 10, thresholdICMPRatio, thresholdNumberOfICMPPackets, weightICMPRatio, weightNumberOfICMPPackets, attackDate)