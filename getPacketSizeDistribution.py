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
        packetSizeDistributionDict[stopTime.strftime("%Y-%m-%dT%H:%M:%SZ")] = PiPS
            
        startTime = startTime + frequency
        j += 1

    p = Path('Calculations')
    q = p / 'Entropy' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    distributionFile = open(str(q) + "/packetSizeDistributions."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", "wb")
    pickle.dump(packetSizeDistributionDict,distributionFile)
    distributionFile.close()

systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
start = "2023-03-08 14:00:00"
stop = "2023-03-08 16:00:00"
frequency = timedelta(minutes = 1)
intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
clusterFrequency = timedelta(minutes = 15)
attackDate="08.03.23"
bucket = "april"
for systemId in systems:
    print(systemId)
    for interval in intervals:
        print(interval)
        calculationEntropyTelemetry(start, stop, systemId, interval, frequency, attackDate)