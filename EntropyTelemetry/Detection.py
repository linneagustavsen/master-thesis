from datetime import datetime,timedelta
import numpy as np
from GetData import *
from GeneralizedEntropy import *
from Distributions import *
from MakePlot import *
import warnings
from influxdb_client.client.warnings import MissingPivotFunction

warnings.simplefilter("ignore", MissingPivotFunction)


'''
    1. Get data to detect on from database continuously.
    2. Make a 5 minute moving average window that gives us a distribution p. (poisson???) (depends on what we want the entropy of)
    3. Calculate entropy of packet size (# bytes/ #packets)??? 
        (pi is: (the number of packets in that 5 min interval that is the size of the ith packet)/(the sum of the number of packets with all sizes) 
        can assume the biggest packet size is 1514 according to a novel approach..)
    4. Calculate entropy of # of packets
    5. Calculate entropy rate of packet size
    6. Calculate information distance between the fractional gaussian noise function (legitimate traffic) and the poisson distribution (attack traffic)
    7. send all these alerts to the sysadmin
'''

def detection(systemId, if_name):
    f = open("EntropyTelemetry/Detections/EntropyPacketSize."+ str(systemId) + "." + str(if_name).replace("/","-") + ".txt", "a")
    f_rate = open("EntropyTelemetry/Detections/EntropyRatePacketSize."+ str(systemId) + "." + str(if_name).replace("/","-") + ".txt", "a")

    packetSizeArray = []
    packetSizeRateArray = []
    packetNumberArray = []
    bytesArray = []
    timeArray = []
    
    startTime = datetime.strptime("2022-10-13 00:00:00", '%Y-%m-%d %H:%M:%S')
    f.write("Time, Change, Value, Mean last 10 minutes")
    f_rate.write("Time, Change, Value, Mean last 10 minutes")
    for i in range(10080):
        timeArray.append(startTime)
        stopTime = startTime + timedelta(minutes = 5)
        dfEgressBytes = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, "egress_stats__if_1sec_octets")
        dfEgressPackets = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, "egress_stats__if_1sec_pkts")
        startTime = startTime + timedelta(minutes = 1)

        if len(dfEgressBytes) <130 or len(dfEgressPackets) <130:
            packetSizeArray.append( np.nan)
            packetSizeRateArray.append( np.nan)
            packetNumberArray.append( np.nan)
            bytesArray.append( np.nan)
            continue

        PiPS,nd = packetSizeDistribution(dfEgressBytes, dfEgressPackets)
        entropyPacketSize = generalizedEntropy(10, PiPS)
        packetSizeArray.append(entropyPacketSize)

        entropyRatePacketSize = entropyPacketSize/nd
        packetSizeRateArray.append(entropyRatePacketSize)

        packetNumberArray.append(sum(dfEgressPackets["_value"].to_numpy()))
        bytesArray.append(sum(dfEgressBytes["_value"].to_numpy()))

        if i < 10:
            continue
        '''if packetSizeArray !=  np.nan and packetSizeArray[i-1] !=  np.nan:
            if abs(packetSizeArray[i] - packetSizeArray[i-1]) > 1:
                print(startTime, "-----The entropy is now:",packetSizeArray[i], "and it was:",packetSizeArray[i-1], "last minute")
                

        if packetSizeRateArray !=  np.nan and packetSizeRateArray[i-1] !=  np.nan:
            if abs(packetSizeRateArray[i] - packetSizeRateArray[i-1]) > 0.015:
                print(startTime, "-----The entropy rate is now:",packetSizeRateArray[i], "and it was:",packetSizeRateArray[i-1], "last minute" )'''
                
        if packetSizeArray !=  np.nan:
            if abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-10: i-1])) > 1:
                print(startTime, "-----The entropy is now:",packetSizeArray[i], "and it was:",np.nanmean(packetSizeArray[i-10: i-1]), "the last 10 minutes")
                f.write("\n" + str(startTime) + "," + str(abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-10: i-1]))) + "," + str(packetSizeArray[i]) + "," + str(np.nanmean(packetSizeArray[i-10: i-1])))

        if packetSizeRateArray !=  np.nan:
            if abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-10: i-1])) > 0.015:
                print(startTime, "-----The entropy rate is now:",packetSizeRateArray[i], "and it was:",np.nanmean(packetSizeRateArray[i-10: i-1]), "the last 10 minutes")
                f_rate.write("\n" + str(startTime) + "," + str(abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-10: i-1]))) + "," + str(packetSizeRateArray[i]) + "," + str(np.nanmean(packetSizeRateArray[i-10: i-1])))
    f.close()
    f_rate.close()
detection("trd-gw", "xe-0/1/0")
