from datetime import timedelta
import sys
from GetThreshold import getThreshold
from GetWeight import getWeight
from NetFlow.Entropy.DetectionFromFile.SrcDetection import detectionSrc

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
thresholdSrcEntropy = getThreshold("srcEntropy", systemId, interval, "Entropy", "NetFlow", attackDate)
thresholdSrcEntropyRate = getThreshold("srcEntropyRate", systemId, interval, "Entropy", "NetFlow", attackDate)

weightSrcEntropy = getWeight("srcEntropy", systemId, interval, "Entropy", "NetFlow", attackDate)
weightSrcEntropyRate = getWeight("srcEntropyRate", systemId, interval, "Entropy", "NetFlow", attackDate)

detectionSrc(start, stop, systemId, frequency, interval, 10, thresholdSrcEntropy, thresholdSrcEntropyRate, weightSrcEntropy, weightSrcEntropyRate, attackDate)