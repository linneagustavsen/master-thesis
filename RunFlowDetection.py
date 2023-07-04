from datetime import timedelta
import sys
from GetThreshold import getThreshold
from GetWeight import getWeight
from NetFlow.Entropy.DetectionFromFile.FlowDetection import detectionFlow

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
thresholdFlowEntropy = getThreshold("flowEntropy", systemId, interval, "Entropy", "NetFlow", attackDate)
thresholdFlowEntropyRate = getThreshold("flowEntropyRate", systemId, interval, "Entropy", "NetFlow", attackDate)
thresholdNumberOfFlows = getThreshold("numberOfFlows", systemId, interval, "Entropy", "NetFlow", attackDate)

weightFlowEntropy = getWeight("flowEntropy", systemId, interval, "Entropy", "NetFlow", attackDate)
weightFlowEntropyRate = getWeight("flowEntropyRate", systemId, interval, "Entropy", "NetFlow", attackDate)
weightNumberOfFlows = getWeight("numberOfFlows", systemId, interval, "Entropy", "NetFlow", attackDate)

detectionFlow(start, stop, systemId, frequency, interval, 10, thresholdFlowEntropy, thresholdFlowEntropyRate, thresholdNumberOfFlows, weightFlowEntropy, weightFlowEntropyRate, weightNumberOfFlows, attackDate)