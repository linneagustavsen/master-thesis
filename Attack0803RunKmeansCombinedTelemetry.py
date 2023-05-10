from datetime import timedelta
import sys
from Telemetry.Kmeans.DetectionFromFile.DetectionCombined import detectionKmeansCombinedTelemetry

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

detectionKmeansCombinedTelemetry(start, stop, arguments[1], timedelta(minutes = 15),interval, 0.5, 0, 0, attackDate)