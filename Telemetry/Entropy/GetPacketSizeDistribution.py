from datetime import datetime,timedelta
from pathlib import Path
import pickle
import numpy as np
from HelperFunctions.GetData import *
from HelperFunctions.GeneralizedEntropy import *
from HelperFunctions.Distributions import *
from HelperFunctions.IsAttack import isAttack
from HelperFunctionsTelemetry.GetDataTelemetry import getData, getDataBytes, getDataPackets

'''
    Calculates entropy and writes calculations to file
    Input:  start:      string, indicating the start time of the data to detect on
            stop:       string, indicating the stop time of the data to detect on
            systemId:   string, name of the system to collect and calculate on  
            if_name:    string, interface name, 
            interval:   timedelta object, size of the sliding window which the calculation is made on,
            frequency:  timedelta object, frequency of metric calculation,
            attackDate: string, date of the attack the calculations are made on
'''

def getPacketSizeDistribution(start, stop, systemId, interval, frequency, attackDate):
    p = Path('Calculations')
    q = p / 'Entropy' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)
    
    packetSizeDistributionDict ={}

    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    intervalTime = (stopTime - startTime).total_seconds()/frequency.total_seconds()
    j = 0
    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + interval
        #Get data for a specified time interval
        dfBytes = getDataBytes(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "april", systemId)
        dfPackets = getDataPackets(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "april", systemId)

        #If there is no data for this interval we skip the calculations
        if dfBytes.empty or dfPackets.empty:
            startTime = startTime + frequency
            continue
        dfBytes = dfBytes["bytes"].to_numpy()
        dfPackets = dfPackets["packets"].to_numpy()

        numberOfPacketsOfSizei = {}
    
        #Loop through the measurements that is collected every 2 sec
        for i in range(len(dfPackets)):
            #If there are no packets the size is 0
            if dfPackets[i] == 0:
                size = 0
            else:
                #If there are packets the average size of a packet is calculated for this measurement, cast to an integer, and stored
                size = int(dfBytes[i]/dfPackets[i])
            #If the size of the packet has been encountered before the number of packets by the number of packets
            if size in numberOfPacketsOfSizei:
                numberOfPacketsOfSizei[size] += dfPackets[i]
            else:
                numberOfPacketsOfSizei[size] = dfPackets[i]
        packetSizeDistributionDict[stopTime.strftime("%Y-%m-%dT%H:%M:%SZ")] = numberOfPacketsOfSizei
       
        #Push the start time by the specified frequency
        startTime = startTime + frequency
        j += 1


    distributionFile = open(str(q) + "/packetSizeDistributions."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", "wb")
    pickle.dump(packetSizeDistributionDict,distributionFile)
    distributionFile.close()