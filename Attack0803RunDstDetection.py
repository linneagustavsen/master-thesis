from datetime import timedelta
from GetThreshold import getThreshold

from NetFlow.Entropy.DetectionFromFile.DstDetection import detectionDst
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
thresholdDstEntropy = getThreshold("dstEntropy", systemId, interval, "Entropy", "NetFlow", attackDate)
thresholdDstEntropyRate = getThreshold("dstEntropyRate", systemId, interval, "Entropy", "NetFlow", attackDate)
detectionDst(start, stop, systemId, frequency, interval, 10, thresholdDstEntropy, thresholdDstEntropyRate, attackDate)