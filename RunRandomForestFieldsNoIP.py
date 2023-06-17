from datetime import timedelta
import sys
from GetWeight import getWeight

from NetFlow.RandomForest.DetectionFromFile.RandomForestDetectionNoIP import detectionRandomForestNoIPNetFlowFields

# Access the command-line arguments
arguments = sys.argv

# Print the arguments
#print("Number of arguments:", len(arguments))
print("Argument values:", arguments)

start = arguments[1]
stop = arguments[2]
frequency = timedelta(minutes = 1)
attackDate= arguments[3]

weight = getWeight("FieldsNoIP", arguments[4], 0, "RandomForest", "NetFlow", attackDate)

detectionRandomForestNoIPNetFlowFields(start, stop, arguments[4], weight, attackDate)