from GetData import *
from datetime import datetime, timedelta
from Check import *

def correlateDetections(file1, file2, file3, start, stop):
    detectionsFile = open("CorrelationTest/DetectionsNoMaxVar" + str(start) + ".txt", "a")
    detectionsFile.write("Time")
    detectionsArray = []

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')


    #time = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),"trd-gw", "xe-0/1/0", "egress_stats__if_1sec_pkts")["_time"].to_numpy()
    stop = False
    timestamp = startTime
    while not stop:
        if timestamp >= stopTime:
            stop = True

            break

        if check(file1, timestamp.strftime('%Y-%m-%d %H:%M')) and check(file2, timestamp.strftime('%Y-%m-%d %H:%M')) and check(file3, timestamp.strftime('%Y-%m-%d %H:%M')):
            detectionsArray.append(timestamp.strftime('%Y-%m-%d %H:%M'))
            detectionsFile.write("\n" + timestamp.strftime('%Y-%m-%d %H:%M'))
        timestamp += timedelta(minutes = 1)
    print(detectionsArray)
    detectionsFile.close()

entropyPacketSizeFile = "EntropyTelemetry/Detections/EntropyPacketSize.2022-09-21 01:00:00.trd-gw.xe-0-1-0.txt"
entropyRatePacketSizeFile = "EntropyTelemetry/Detections/EntropyRatePacketSize.2022-09-21 01:00:00.trd-gw.xe-0-1-0.txt"
thresholdPacketsFile = "ThresholdTelemetry/Detections/2022-09-21 01:00:00.trd-gw.xe-0-1-0.egress_stats__if_1sec_pkts.txt"
#thresholdPacketsMaxVarFile = "ThresholdTelemetry/Detections/2022-09-21 01:00:00.trd-gw.xe-0-1-0.egress_stats__if_1sec_pkts.MaxVar.txt"

correlateDetections(entropyPacketSizeFile, entropyRatePacketSizeFile, thresholdPacketsFile, "2022-09-21 01:00:00", "2022-09-22 00:00:00")
'''
entropyPacketSizeFile = "EntropyTelemetry/Detections/EntropyPacketSize.trd-gw.xe-0-1-0.txt"
entropyRatePacketSizeFile = "EntropyTelemetry/Detections/EntropyRatePacketSize.trd-gw.xe-0-1-0.txt"
thresholdPacketsFile = "ThresholdTelemetry/Detections/trd-gw.xe-0-1-0.egress_stats__if_1sec_pkts.txt"
thresholdPacketsMaxVarFile = "ThresholdTelemetry/Detections/trd-gw.xe-0-1-0.egress_stats__if_1sec_pkts.MaxVar.txt"
correlateDetections(entropyPacketSizeFile, entropyRatePacketSizeFile, thresholdPacketsFile, thresholdPacketsMaxVarFile, "2022-10-13 00:00:00", "2022-10-20 00:00:00")'''