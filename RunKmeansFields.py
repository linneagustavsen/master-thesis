from datetime import timedelta
import sys
from GetWeight import getWeight
from NetFlow.Kmeans.DetectionFromFile.DetectionKmeans import detectionKmeans

# Access the command-line arguments
arguments = sys.argv

# Print the arguments
#print("Number of arguments:", len(arguments))
print("Argument values:", arguments)

start = arguments[1]
stop = arguments[2]
frequency = timedelta(minutes = 1)
attackDate= arguments[3]


weight = getWeight("Fields", arguments[4], 0, "Kmeans", "NetFlow", attackDate)

detectionKmeans(start, stop, arguments[4], timedelta(minutes = 15), 0.5, 0, 0, weight, attackDate)