import numpy as np
from datetime import datetime,timedelta
import matplotlib.dates as mdates
from scipy.stats import norm
from GetData import *
from GeneralizedEntropy import *
from PacketSizeDistribution import *
from NumberOfPacketsDistribution import *
from MakePlot import *
import pandas as pd
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

    time = ["2022-10-13T11:00:00Z", "2022-10-13T11:05:00Z", "2022-10-13T11:10:00Z", "2022-10-13T11:15:00Z", "2022-10-13T11:20:00Z", "2022-10-13T11:25:00Z",
    "2022-10-13T11:30:00Z", "2022-10-13T11:35:00Z", "2022-10-13T11:40:00Z", "2022-10-13T11:45:00Z", "2022-10-13T11:50:00Z", "2022-10-13T11:55:00Z", 
    "2022-10-13T12:00:00Z","2022-10-13T12:05:00Z", "2022-10-13T12:10:00Z", "2022-10-13T12:15:00Z", "2022-10-13T12:20:00Z", "2022-10-13T12:25:00Z",
    "2022-10-13T12:30:00Z", "2022-10-13T12:35:00Z", "2022-10-13T12:40:00Z", "2022-10-13T12:45:00Z", "2022-10-13T12:50:00Z", "2022-10-13T12:55:00Z",
    "2022-10-13T13:00:00Z", "2022-10-13T13:05:00Z", "2022-10-13T13:10:00Z", "2022-10-13T13:15:00Z", "2022-10-13T13:20:00Z", "2022-10-13T13:25:00Z",
    "2022-10-13T13:30:00Z", "2022-10-13T13:35:00Z", "2022-10-13T13:40:00Z", "2022-10-13T13:45:00Z", "2022-10-13T13:50:00Z", "2022-10-13T13:55:00Z", "2022-10-13T14:00:00Z"]
    packetSizeArray = []
    packetNumberArray = []
    packetSizeRateArray = []
    timeArray = []
    startTime = datetime.strptime("2022-10-13 00:00:00", '%Y-%m-%d %H:%M:%S')

    for i in range(2016):
        timeArray.append(startTime)
        stopTime = startTime + timedelta(minutes = 5)
        dfEgressBytes = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, "egress_stats__if_1sec_octets")
        dfEgressPackets = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, "egress_stats__if_1sec_pkts")
        startTime = stopTime

        if len(dfEgressBytes) <130 or len(dfEgressPackets) <130:
            packetSizeArray.append(None)
            packetNumberArray.append(None)
            packetSizeRateArray.append(None)
            continue

        PiPS,nd = packetSizeDistribution(dfEgressBytes, dfEgressPackets)
        entropyPacketSize = generalizedEntropy(10, PiPS)
        packetSizeArray.append(entropyPacketSize)

        PiNP = numberOfPacketsDistribution(dfEgressPackets)
        entropyNumberOfPackets = generalizedEntropy(10, PiNP)
        packetNumberArray.append(entropyNumberOfPackets)

        entropyRatePacketSize = entropyPacketSize/nd
        packetSizeRateArray.append(entropyRatePacketSize)

    makePlot(packetSizeArray, timeArray, "Entropy of packet size")
    makePlot(packetNumberArray, timeArray, "Entropy of packet number")
    makePlot(packetSizeRateArray, timeArray, "Entropy rate of packet size")

    #If it changes by 1 it is pretty significant

detection("trd-gw", "xe-0/1/0")
