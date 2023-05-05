from pathlib import Path
from HelperFunctions.GetData import *
from datetime import datetime
import pandas as pd
from HelperFunctions.StructureData import *
import numpy as np

'''
    Make a dataset to use for either training or testing a Random Forest classifier
    Input:  silkFile:   string, file with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            path:       string, path to the dataset
            attackDate: string, date of the attack the calculations are made on
    Output: dataSet:    pandas dataframe, contains the dataset         
'''
def makeDataSetNetFlow(silkFile, start, stop, frequency, interval, path, systemId, attackDate):
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    p = Path('NetFlow')
    q = p /'RandomForest'/ 'DataSets' 
    fieldsFile = str(q) + "/" + str(path) +"/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"
    if Path(fieldsFile).exists():
        with open(str(fieldsFile), 'rb') as f:
            df = np.load(f, allow_pickle=True)
    else:
        print("Cant find", fieldsFile)
        if not q.exists():
            q.mkdir(parents=True, exist_ok=False)
        df = getDataNetFlow(silkFile, startTime, stopTime)
        with open(str(fieldsFile), 'wb') as f:
            np.save(f, df)

    if len(df) <2:
        return []
    print(df[0])
    sTime, eTime, measurements, labels = structureDataNumpyArrays(df)
    print(measurements[0])
    data = []
    entropyFile =  str(q) + "/" + str(path) +"/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"
    if Path(entropyFile).exists():
        with open(str(entropyFile), 'rb') as f:
            entropy_df = np.load(f, allow_pickle=True)
    else:
        print("Cant find", entropyFile)
        if not q.exists():
            q.mkdir(parents=True, exist_ok=False)
        entropy_df = getEntropyDataNetFlow(silkFile, start, stop, frequency, interval)
        with open(str(entropyFile), 'wb') as f:
            np.save(f, entropy_df)

    if len(entropy_df) <2:
        return []
    entropy_intervals, entropy_measurements, entropy_labels = structureDataEntropyNumpyArrays(entropy_df)

    now = datetime.now()

    lastYear = now.year
    lastMonth = now.month
    lastDay = now.day
    lastHour = now.hour
    lastMinute = now.minute
    counter = 0
    for timestamp in sTime:
        curYear = timestamp.year
        curMonth = timestamp.month
        curDay = timestamp.day
        curHour = timestamp.hour
        curMinute = timestamp.minute
        
        if not (lastYear == curYear and lastMonth == curMonth and lastDay == curDay and lastHour == curHour and lastMinute == curMinute):
            for entropy_interval in entropy_intervals:
                if timestamp.replace(second = 0, microsecond = 0) in entropy_interval:
                    indexArray = np.where(entropy_intervals == entropy_interval)
            
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

        packetSizeArray = entropy_measurements[indexInTimeArray][9]
        packetSizeRateArray = entropy_measurements[indexInTimeArray][10]

        curMeasurements = measurements[counter]

        newMeasurements = [ipSrcArray, ipSrcRateArray, ipDstArray, ipDstRateArray, flowArray, flowRateArray, packetSizeArray, packetSizeRateArray, labels[counter]]

        times = [sTime[counter], eTime[counter]]

        times.extend(curMeasurements)
        times.extend(newMeasurements)
        data.append(times)

        counter +=1
    data = np.array(data)

    with open(str(q) + "/" +str(path) + "/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'wb') as f:
        np.save(f, data)
    #return data

'''
    Make a dataset to use for either training or testing a Random Forest classifier
    Specifically without IPs
    Input:  silkFile:   string, file with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            path:       string, path to the dataset
            attackDate: string, date of the attack the calculations are made on
    Output: dataSet:    pandas dataframe, contains the dataset       
'''
def makeDataSetNoIPNetFlow(silkFile, start, stop, frequency, interval, path, systemId, attackDate):
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    p = Path('NetFlow')
    q = p /'RandomForest'/ 'DataSets' 

    fieldsFile = str(q) + "/" + str(path) +"/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"
    fieldsFileNoIP = str(q) + "/" + str(path) +"/FieldsNoIP.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"
    if Path(fieldsFileNoIP).exists():
        with open(str(fieldsFileNoIP), 'rb') as f:
            df = np.load(f, allow_pickle=True)
    elif Path(fieldsFile).exists():
        with open(str(fieldsFile), 'rb') as f:
            df0 = np.load(f, allow_pickle=True)
        df1 = np.delete(df0, np.s_[2:4],1)
        df = np.delete(df1, -2,1)
    else:
        print("Cant find", fieldsFileNoIP)
        if not q.exists():
            q.mkdir(parents=True, exist_ok=False)
        df = getDataNetFlowNoIP(silkFile, startTime, stopTime)
        with open(str(fieldsFileNoIP), 'wb') as f:
            np.save(f, df)
    if len(df) <2:
        return []
    print(df[0])
    sTime, eTime, measurements, labels = structureDataNumpyArrays(df)
    print(measurements[0])
    data = []

    entropyFile =  str(q) + "/" + str(path) +"/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"
    if Path(entropyFile).exists():
        with open(str(entropyFile), 'rb') as f:
            entropy_df = np.load(f, allow_pickle=True)
    else:
        print("Cant find", entropyFile)
        if not q.exists():
            q.mkdir(parents=True, exist_ok=False)
        entropy_df = getDataNetFlowNoIP(silkFile, start, stop, frequency, interval)
        with open(str(entropyFile), 'wb') as f:
            np.save(f, entropy_df)
    if len(entropy_df) <2:
        return []
    entropy_intervals, entropy_measurements, entropy_labels = structureDataEntropyNumpyArrays(entropy_df)

    now = datetime.now()

    lastYear = now.year
    lastMonth = now.month
    lastDay = now.day
    lastHour = now.hour
    lastMinute = now.minute
    counter = 0
    for timestamp in sTime:
        #timestamp = datetime.utcfromtimestamp(((sTime[i] - np.datetime64('1970-01-01T00:00:00'))/ np.timedelta64(1, 's')))
        curYear = timestamp.year
        curMonth = timestamp.month
        curDay = timestamp.day
        curHour = timestamp.hour
        curMinute = timestamp.minute
        
        if not (lastYear == curYear and lastMonth == curMonth and lastDay == curDay and lastHour == curHour and lastMinute == curMinute):
            for entropy_interval in entropy_intervals:
                if timestamp.replace(second = 0, microsecond = 0) in entropy_interval:
                    indexArray = np.where(entropy_intervals == entropy_interval)
            
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

        packetSizeArray = entropy_measurements[indexInTimeArray][9]
        packetSizeRateArray = entropy_measurements[indexInTimeArray][10]

        curMeasurements = measurements[counter]
        
        newMeasurements = [ipSrcArray, ipSrcRateArray, ipDstArray, ipDstRateArray, flowArray, flowRateArray, packetSizeArray, packetSizeRateArray, labels[counter]]
        times = [sTime[counter], eTime[counter]]
        times.extend(curMeasurements)
        times.extend(newMeasurements)
        data.append(times)

        counter += 1
    data = np.array(data)
 
    with open(str(q) + "/" +str(path) + "/CombinedNoIP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'wb') as f:
        np.save(f, data)
    #return data
    
    
'''silkFile="/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-01_10-11-sorted.rw"
start = "2011-01-01 10:00:00"
stop = "2011-01-01 12:00:00"
systemId = "oslo-gw"
frequency = timedelta(minutes=1)
interval = timedelta(minutes=5)
trainingSet = makeDataSetNetFlow(silkFile, start, stop, systemId, frequency, interval, "Training")
trainingSet.to_pickle("NetFlow/RandomForest/RawData/TrainingSet."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
print(trainingSet.head)    

silkFile="/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-02_10-11-sorted.rw"
start = "2011-01-02 10:00:00"
stop = "2011-01-02 12:00:00"
systemId = "oslo-gw"
frequency = timedelta(minutes=1)
interval = timedelta(minutes=5)
testingSet = makeDataSetNetFlow(silkFile, start, stop, systemId, frequency, interval, "Testing")
testingSet.to_pickle("NetFlow/RandomForest/RawData/TestingSet."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
print(testingSet.head)'''