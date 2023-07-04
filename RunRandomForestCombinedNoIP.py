from datetime import timedelta
import sys
from GetWeight import getWeight
from NetFlow.RandomForest.DetectionFromFile.RandomForestDetectionCombinedNoIP import detectionRandomForestNoIPNetFlow

# Access the command-line arguments
arguments = sys.argv

# Print the arguments
#print("Number of arguments:", len(arguments))
print("Argument values:", arguments)

start = arguments[1]
stop = arguments[2]
frequency = timedelta(minutes = 1)
attackDate= arguments[3]

weight = getWeight("CombinedNoIP", arguments[4], timedelta(minutes=int(arguments[5])), "RandomForest", "NetFlow", attackDate)

detectionRandomForestNoIPNetFlow(start, stop, arguments[4], timedelta(minutes=int(arguments[5])), weight, attackDate)