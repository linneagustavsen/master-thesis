from datetime import timedelta
import sys
from NetFlow.Kmeans.DetectionFromFile.DetectionKmeansCombined import detectionKmeansCombined

# Access the command-line arguments
arguments = sys.argv

# Print the arguments
#print("Number of arguments:", len(arguments))
print("Argument values:", arguments)

start = arguments[1]
stop = arguments[2]
frequency = timedelta(minutes = 1)
attackDate= arguments[3]
if int(arguments[5]) != 15:
    clusterFrequency = timedelta(minutes=15)
else:
    clusterFrequency = timedelta(minutes=30)

detectionKmeansCombined(start, stop, arguments[4], timedelta(minutes=int(arguments[5])), clusterFrequency, 0.5, 0, 0, attackDate)