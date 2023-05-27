from datetime import timedelta

from Telemetry.Threshold.DetectionFromFile.DetectionMaxVar import detectionMaxVar
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

detectionMaxVar(start, stop, arguments[4], arguments[5], 0, attackDate)