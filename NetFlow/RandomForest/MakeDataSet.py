from .GetData import *
from datetime import datetime,timedelta
import pandas as pd
from HelperFunctions.StructureData import *
import numpy as np
def makeDataSet(silkFile, start, stop, systemId, frequency, interval, path, attackDate):
    columTitles = ["srcIP","dstIP","srcPort","dstPort","protocol","packets","bytes","fin","syn","rst","psh","ack","urg","ece","cwr","duration", "nestHopIP", "entropy_ip_source","entropy_rate_ip_source","entropy_ip_destination","entropy_rate_ip_destination","entropy_flow","entropy_rate_flow","number_of_flows","icmp_ratio","number_of_icmp_packets", "label"]
    
    df = getData(silkFile, start, stop)
    df.to_pickle("NetFlow/RandomForest/RawData/"+path+".attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #df = pd.read_pickle("NetFlow/RandomForest/RawData/"+path+".attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    sTime, eTime, measurements = structureData(df)
    data = np.empty((len(sTime),len(columTitles)))

    entropy_df = getEntropyData(silkFile, start, stop, frequency, interval)
    entropy_df.to_pickle("NetFlow/RandomForest/RawData/"+path+"Entropy.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #entropy_df = pd.read_pickle("NetFlow/RandomForest/RawData/"+path+"Entropy.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")   
    entropy_timeStamps, entropy_measurements = structureDataEntropy(entropy_df)

    now = datetime.now()

    lastYear = now.year
    lastMonth = now.month
    lastDay = now.day
    lastHour = now.hour
    lastMinute = now.minute
    
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
        curMeasurements = measurements[i][:-1]

        newMeasurements = np.array([ipSrcArray, ipSrcRateArray, ipDstArray, ipDstRateArray, flowArray, flowRateArray, numberOfFlows, icmpRatioArray, icmpPacketsArray, measurements[i][-1]])

        curMeasurements = np.concatenate((curMeasurements,newMeasurements), axis=None)

        data[i] = curMeasurements
    dataSet = pd.DataFrame(data, columns=columTitles)
    return dataSet
    
'''silkFile="/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-01_10-11-sorted.rw"
start = "2011-01-01 10:00:00"
stop = "2011-01-01 12:00:00"
systemId = "oslo-gw"
frequency = timedelta(minutes=1)
interval = timedelta(minutes=5)
trainingSet = makeDataSet(silkFile, start, stop, systemId, frequency, interval, "Training")
trainingSet.to_pickle("NetFlow/RandomForest/RawData/TrainingSet.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
print(trainingSet.head)    

silkFile="/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-02_10-11-sorted.rw"
start = "2011-01-02 10:00:00"
stop = "2011-01-02 12:00:00"
systemId = "oslo-gw"
frequency = timedelta(minutes=1)
interval = timedelta(minutes=5)
testingSet = makeDataSet(silkFile, start, stop, systemId, frequency, interval, "Testing")
testingSet.to_pickle("NetFlow/RandomForest/RawData/TestingSet.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
print(testingSet.head)'''