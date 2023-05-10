from datetime import timedelta
import sys
from NetFlow.Entropy.DetectionFromFile.SrcDetection import detectionSrc

# Access the command-line arguments
arguments = sys.argv

# Print the arguments
print("Number of arguments:", len(arguments))
print("Argument values:", arguments)

start = "2023-03-08 14:15:00"
stop = "2023-03-08 16:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 10)
attackDate="08.03.23"

detectionSrc(start, stop, arguments[1], frequency, interval, 10, 0, 0, attackDate)