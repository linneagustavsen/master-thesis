from sklearn.cluster import KMeans
import numpy as np
from datetime import datetime
from .GetData import *
from HelperFunctions.StructureData import *
import pandas as pd
import pickle

def trainingCombined(silkFile, start, stop, systemId, frequency, interval, attackDate):
    columTitles = ["srcIP","dstIP","srcPort","dstPort","protocol","packets","bytes","fin","syn","rst","psh","ack","urg","ece","cwr","duration", "nestHopIP", "entropy_ip_source","entropy_rate_ip_source","entropy_ip_destination","entropy_rate_ip_destination","entropy_flow","entropy_rate_flow","number_of_flows","icmp_ratio","number_of_icmp_packets"]
    
    '''df = getData(silkFile)
    df.to_pickle("NetFlow/Kmeans/RawData/TrainingData.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")'''
    df = pd.read_pickle("NetFlow/Kmeans/RawData/TrainingData.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    sTime, eTime, measurements = structureData(df)
    data = np.empty((len(sTime),len(columTitles)))
    print("Structured Data")
    '''entropy_df = getEntropyData(silkFile, start, stop, frequency, interval)
    entropy_df.to_pickle("NetFlow/Kmeans/RawData/TrainingDataEntropy.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")'''
    entropy_df = pd.read_pickle("NetFlow/Kmeans/RawData/TrainingDataEntropy.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")   
    entropy_timeStamps, entropy_measurements = structureDataEntropy(entropy_df)
    print("Got entropy data")

    now = datetime.now()

    lastYear = now.year
    lastMonth = now.month
    lastDay = now.day
    lastHour = now.hour
    lastMinute = now.minute
    
    print("Start loop")
    for i in range(len(sTime)):
        timestamp = datetime.utcfromtimestamp(((sTime[i] - np.datetime64('1970-01-01T00:00:00'))/ np.timedelta64(1, 's')))
        curYear = timestamp.year
        curMonth = timestamp.month
        curDay = timestamp.day
        curHour = timestamp.hour
        curMinute = timestamp.minute
        
        if not (lastYear == curYear and lastMonth == curMonth and lastDay == curDay and lastHour == curHour and lastMinute == curMinute):
            indexArray = np.where(entropy_timeStamps == timestamp.strftime("%Y-%m-%d %H:%M"))
            if len(indexArray[0]) == 0:
                continue
            indexInTimeArray = indexArray[0][0]
            lastYear = curYear
            lastMonth = curMonth
            lastDay = curDay
            lastHour = curHour
            lastMinute = curMinute
            
        ipSrcArray = entropy_measurements[indexInTimeArray][0]
        ipSrcRateArray = entropy_measurements[indexInTimeArray][1]

        ipDstArray = entropy_measurements[indexInTimeArray][2]
        ipDstRateArray = entropy_measurements[indexInTimeArray][3]

        flowArray = entropy_measurements[indexInTimeArray][4]
        flowRateArray = entropy_measurements[indexInTimeArray][5]

        numberOfFlows = entropy_measurements[indexInTimeArray][6]

        icmpRatioArray = entropy_measurements[indexInTimeArray][7]
        icmpPacketsArray = entropy_measurements[indexInTimeArray][8]
        curMeasurements = measurements[i]

        newMeasurements = np.array([ipSrcArray, ipSrcRateArray, ipDstArray, ipDstRateArray, flowArray, flowRateArray, numberOfFlows, icmpRatioArray, icmpPacketsArray])

        curMeasurements = np.concatenate((curMeasurements,newMeasurements), axis=None)

        data[i] = curMeasurements
    
    trainingSet = pd.DataFrame(data, columns=columTitles)
    trainingSet.to_pickle("NetFlow/Kmeans/RawData/TrainingDataCombined.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")

    kmeans = KMeans(n_clusters=2, random_state=0, n_init="auto").fit(trainingSet)
    pickle.dump(kmeans, open("NetFlow/Kmeans/Models/MLmodelCombined.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", 'wb'))
'''
silkFile="/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-01_10-11-sorted.rw"
start = "2011-01-01 10:00:00"
stop = "2011-01-01 12:00:00"
systemId = "oslo-gw"
frequency = timedelta(minutes=1)
interval = timedelta(minutes=5)
trainingCombined(silkFile, start, stop, systemId, frequency, interval)'''