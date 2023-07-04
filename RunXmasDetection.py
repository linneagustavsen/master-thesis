from datetime import timedelta
from GetWeight import getWeight

from NetFlow.Threshold.DetectionFromFile.XmasDetection import xmasCalculation
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

weight = getWeight("Xmas", arguments[4], 0, "Threshold", "NetFlow", attackDate)

xmasCalculation(start, stop, arguments[4], weight, attackDate)