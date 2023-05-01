from pathlib import Path
import numpy as np
from datetime import datetime
from HelperFunctions.GetData import *
from HelperFunctions.StructureData import *
import pandas as pd

'''
    Make a dataset to use for testing a K-means clustering algorithm
    Input:  
            silkFile:   string, file with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            attackDate: string, date of the attack the calculations are made on
    Output: 
            dataSet:    pandas dataframe, contains the dataset         
'''
def makeDataSetKmeansNetFlow(silkFile, start, stop, frequency, interval):
    columTitles = ["srcIP","dstIP","srcPort","dstPort","protocol","packets","bytes","fin","syn","rst","psh","ack","urg","ece","cwr","duration", "nestHopIP", "entropy_ip_source","entropy_rate_ip_source","entropy_ip_destination","entropy_rate_ip_destination","entropy_flow","entropy_rate_flow","number_of_flows","icmp_ratio","number_of_icmp_packets","packet_size_entropy","packet_size_entropy_rate","number_of_packets","number_of_bytes", "label"]
    
    df = getDataNetFlow(silkFile, start, stop)
    sTime, eTime, measurements = structureDataNumpyArrays(df)
    data = np.empty((len(sTime),len(columTitles)))

    entropy_df = getEntropyDataNetFlow(silkFile, start.strftime("%Y-%m-%d %H:%M:%S"), stop.strftime("%Y-%m-%d %H:%M:%S"), frequency, interval)
    entropy_timeStamps, entropy_measurements = structureDataEntropyNumpyArrays(entropy_df)

    now = datetime.now()

    lastYear = now.year
    lastMonth = now.month
    lastDay = now.day
    lastHour = now.hour
    lastMinute = now.minute

    for i in range(len(sTime)):
        
        #timestamp = datetime.utcfromtimestamp(((sTime[i] - np.datetime64('1970-01-01T00:00:00'))/ np.timedelta64(1, 's')))
        timestamp = sTime[i]
        curYear = timestamp.year
        curMonth = timestamp.month
        curDay = timestamp.day
        curHour = timestamp.hour
        curMinute = timestamp.minute
        
        if not (lastYear == curYear and lastMonth == curMonth and lastDay == curDay and lastHour == curHour and lastMinute == curMinute):
            indexArray = np.where(entropy_timeStamps == timestamp.replace(second = 0, microsecond = 0))
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

        packetSizeArray = entropy_measurements[indexInTimeArray][9]
        packetSizeRateArray = entropy_measurements[indexInTimeArray][10]

        packetNumberArray = entropy_measurements[indexInTimeArray][11]
        bytesArray = entropy_measurements[indexInTimeArray][12]

        curMeasurements = measurements[i][:-1]

        newMeasurements = np.array([ipSrcArray, ipSrcRateArray, ipDstArray, ipDstRateArray, flowArray, flowRateArray, numberOfFlows, icmpRatioArray, icmpPacketsArray, packetSizeArray, packetSizeRateArray, packetNumberArray, bytesArray, measurements[i][-1]])

        curMeasurements = np.concatenate((curMeasurements,newMeasurements), axis=None)

        data[i] = curMeasurements
    
    testingSet = pd.DataFrame(data, columns=columTitles)
    sTimes = pd.to_datetime(sTime)
    eTimes = pd.to_datetime(eTime)
    testingSet.insert(0, "sTime", sTimes)
    testingSet.insert(1, "eTime", eTimes)
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
'''
baseFile="two-hours-2011-02-08_10-12-sorted.rw"         
systemId = "oslo-gw1"
start = "2011-02-08 10:00:00"
stop = "2011-02-08 12:00:00"
startCombined = "2011-02-08 10:00:00"
stopCombined = "2011-02-08 12:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 10)
pathToRawFiles="/home/linneafg/silk-data/RawDataFromFilter/"
attackDate="08.02.11"
silkFile = pathToRawFiles+systemId + "/"+ baseFile
windowSize = 10

testingSet = makeDataSetKmeansNetFlow(silkFile, start, stop, systemId, frequency, interval, attackDate)
p = Path('NetFlow')
q = p / 'Kmeans' / 'DataSets'

if not q.exists():
    q = Path('Kmeans')
    q = q / 'DataSets'
testingPath = q / 'Testing'

if not testingPath.exists():
    testingPath.mkdir()
testingSet.to_pickle(str(testingPath) + "/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
'''