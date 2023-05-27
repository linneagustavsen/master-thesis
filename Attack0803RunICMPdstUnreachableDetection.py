from datetime import timedelta

from NetFlow.Threshold.DetectionFromFile.ICMPDstUnreachableDetection import icmpDstUnreachableDetection
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

icmpDstUnreachableDetection(start, stop, arguments[4], frequency, timedelta(minutes=int(arguments[5])), 10, 0, attackDate)