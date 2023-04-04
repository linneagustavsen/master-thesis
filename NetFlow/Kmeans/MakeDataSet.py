import numpy as np
from datetime import datetime
from HelperFunctions.GetData import *
from HelperFunctions.StructureData import *
import pandas as pd

'''
    Make a dataset to use for testing a K-means clustering algorithm
    Input:  silkFile:   string, File with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            attackDate: string, date of the attack the calculations are made on
    Output: dataSet:    pandas dataframe, contains the dataset         
'''
def makeTestingDataCombined(silkFile, start, stop, systemId, frequency, interval, attackDate):
    columTitles = ["srcIP","dstIP","srcPort","dstPort","protocol","packets","bytes","fin","syn","rst","psh","ack","urg","ece","cwr","duration", "nestHopIP", "entropy_ip_source","entropy_rate_ip_source","entropy_ip_destination","entropy_rate_ip_destination","entropy_flow","entropy_rate_flow","number_of_flows","icmp_ratio","number_of_icmp_packets","label"]
    
    df = getDataNetFlow(silkFile, start, stop)
    df.to_pickle("NetFlow/Kmeans/RawData/TestingData.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #df = pd.read_pickle("NetFlow/Kmeans/RawData/TestingData.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    sTime, eTime, measurements = structureData(df)
    data = np.empty((len(sTime),len(columTitles)))
    entropy_df = getEntropyDataNetFlow(silkFile, start, stop, frequency, interval)
    entropy_df.to_pickle("NetFlow/Kmeans/RawData/TestingDataEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #entropy_df = pd.read_pickle("NetFlow/Kmeans/RawData/TestingDataEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
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
    
    testingSet = pd.DataFrame(data, columns=columTitles)
    testingSet.insert(0, "time", sTime)
    return testingSet
'''
silkFile="/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-02_10-11-sorted.rw"
start = "2011-01-02 10:00:00"
stop = "2011-01-02 12:00:00"
systemId = "oslo-gw"
frequency = timedelta(minutes=1)
interval = timedelta(minutes=5)
testingSet = makeTestingDataCombined(silkFile, start, stop, systemId, frequency, interval, attackDate)
testingSet.to_pickle("NetFlow/Kmeans/RawData/TestingDataCombined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
'''