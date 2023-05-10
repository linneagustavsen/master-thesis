from datetime import timedelta
import sys
from NetFlow.Kmeans.DetectionFromFile.DetectionKmeansEntropy import detectionKmeansEntropy

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

detectionKmeansEntropy(arguments[1], interval, 0.5, 0, 0, attackDate)