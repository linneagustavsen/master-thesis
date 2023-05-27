from datetime import timedelta
import sys
from NetFlow.Entropy.DetectionFromFile.SYNEntropyDetection import synEntropyDetection
# Access the command-line arguments
arguments = sys.argv

# Print the arguments
#print("Number of arguments:", len(arguments))
print("Argument values:", arguments)

start = arguments[1]
stop = arguments[2]
frequency = timedelta(minutes = 1)
attackDate= arguments[3]

synEntropyDetection(start, stop, arguments[4], frequency, timedelta(minutes=int(arguments[5])), 10, 0, 0, 0, attackDate)