from datetime import timedelta
import sys
from NetFlow.Kmeans.DetectionFromFile.DetectionKmeansCombined import detectionKmeansCombined

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

detectionKmeansCombined(start, stop, arguments[1], interval, timedelta(minutes = 15), 0.5, 0, 0, attackDate)