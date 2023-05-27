from datetime import timedelta

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

synDetection(start, stop, arguments[4], 10, 0, attackDate)