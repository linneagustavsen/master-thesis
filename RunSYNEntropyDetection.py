from datetime import timedelta
import sys
from GetThreshold import getThreshold
from GetWeight import getWeight
from NetFlow.Entropy.DetectionFromFile.SYNEntropyDetection import synEntropyDetection
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
thresholdSrc = getThreshold("SYN.srcEntropy", systemId, interval, "Entropy", "NetFlow", attackDate)
thresholdDst = getThreshold("SYN.dstEntropy", systemId, interval, "Entropy", "NetFlow", attackDate)
thresholdFlow = getThreshold("SYN.flowEntropy", systemId, interval, "Entropy", "NetFlow", attackDate)

weightSrc = getWeight("SYN.srcEntropy", systemId, interval, "Entropy", "NetFlow", attackDate)
weightDst = getWeight("SYN.dstEntropy", systemId, interval, "Entropy", "NetFlow", attackDate)
weightFlow = getWeight("SYN.flowEntropy", systemId, interval, "Entropy", "NetFlow", attackDate)

synEntropyDetection(start, stop, systemId, frequency, interval, 10, thresholdSrc, thresholdDst, thresholdFlow, weightSrc, weightDst, weightFlow, attackDate)