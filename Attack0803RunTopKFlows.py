from datetime import timedelta
import sys
from GetThreshold import getThreshold
from NetFlow.TopKFlows.DetectionFromFile.topkflowDetection import topkflows

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
threshold = getThreshold("TopKFlows", systemId, 0, "TopKFlows", "NetFlow", attackDate)

topkflows(start, stop, systemId, threshold, attackDate)