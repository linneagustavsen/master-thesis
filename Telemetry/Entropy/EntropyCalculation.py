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

def calculationEntropyTelemetry(start, stop, systemId, interval, frequency, attackDate):
    p = Path('Calculations')
    q = p / 'Entropy' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)
    #Open file to write alerts to
    calculations = open(str(q) + "/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #Write the column titles to the files
    calculations.write("sTime,eTime,entropy_packet_size,entropy_rate_packet_size,numberOfPackets,numberOfBytes,real_label")

    #Instantiate empty arrays for the calculated values
    packetSizeArray = []
    packetSizeRateArray = []
    packetNumberArray = []
    bytesArray = []
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

        #Find the probability distribution based on how big the packets are this time interval
        PiPS,nps = packetSizeDistribution(dfBytes, dfPackets)
        #Calculate the generalized entropy of this distribution
        entropyPacketSize = generalizedEntropy(10, PiPS)
        packetSizeArray.append(entropyPacketSize)
        #Calculate the generalized entropy rate of this distribution
        packetSizeRateArray.append(entropyPacketSize/nps)
        packetSizeDistributionDict[stopTime.strftime("%Y-%m-%dT%H:%M:%SZ")] = PiPS
        
        #Store the number of packets and bytes this time interval
        packetNumberArray.append(sum(dfPackets))
        bytesArray.append(sum(dfBytes))
        if j == 0:
            sTime = startTime
        else:
            sTime =stopTime - frequency
            
        #If there is not enough stored values to compare with we skip the detection
        calculations.write("\n" + sTime.strftime("%Y-%m-%dT%H:%M:%SZ")+ ","+ stopTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(packetSizeArray[j]) + "," + str(packetSizeRateArray[j])
                               + "," + str(packetNumberArray[j]) + "," + str(bytesArray[j]) +  "," + str(int(isAttack(sTime, stopTime))))

        #Push the start time by the specified frequency
        startTime = startTime + frequency
        j += 1

    calculations.close()

    distributionFile = open(str(q) + "/packetSizeDistributions."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", "wb")
    pickle.dump(packetSizeDistributionDict,distributionFile)
    distributionFile.close()