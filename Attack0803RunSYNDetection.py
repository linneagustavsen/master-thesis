from datetime import timedelta
from GetThreshold import getThreshold

from NetFlow.Threshold.DetectionFromFile.SYNDetection import synDetection
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
threshold = getThreshold("SYN", systemId, 0, "Threshold", "NetFlow", attackDate)

synDetection(start, stop, systemId, 10, threshold, attackDate)