from HelperFunctions.GetData import *
from datetime import datetime, timedelta
from Check import *


detectionsFile = open("CorrelationTest/Detections/DetectionsWithKmeansNoMaxVar.txt", "a")
detectionsFile.write("Time")
detectionsArray = []

startTime = datetime.strptime("2022-10-13 00:00:00", '%Y-%m-%d %H:%M:%S')
stopTime = datetime.strptime("2022-10-20 00:00:00", '%Y-%m-%d %H:%M:%S')


#time = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),"trd-gw", "xe-0/1/0", "egress_stats__if_1sec_pkts")["_time"].to_numpy()
stop = False
timestamp = startTime
while not stop:
    if timestamp >= stopTime:
        stop = True

        break

    if check("CorrelationTest/Detections/Combined.Cluster0.trd-gw.xe-0-1-0.txt", timestamp.strftime('%Y-%m-%d %H:%M')) and check("Telemetry/Entropy/Detections/EntropyPacketSize.trd-gw.xe-0-1-0.txt", timestamp.strftime('%Y-%m-%d %H:%M')) and check("Telemetry/Entropy/Detections/EntropyRatePacketSize.trd-gw.xe-0-1-0.txt", timestamp.strftime('%Y-%m-%d %H:%M')) and check("Telemetry/Threshold/Detections/trd-gw.xe-0-1-0.egress_stats__if_1sec_pkts.txt", timestamp.strftime('%Y-%m-%d %H:%M')):
        detectionsArray.append(timestamp.strftime('%Y-%m-%d %H:%M'))
        detectionsFile.write("\n" + timestamp.strftime('%Y-%m-%d %H:%M'))
    timestamp += timedelta(minutes = 1)
print(detectionsArray)
detectionsFile.close()