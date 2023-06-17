from pathlib import Path
from HelperFunctions.IsAttack import isAttack
from HelperFunctionsTelemetry.GetDataTelemetry import *
from datetime import datetime,timedelta
import pandas as pd
from HelperFunctions.StructureData import *
import numpy as np
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *

'''
    Make a dataset to use for either training or testing a Random Forest classifier
    Input:  systemId:   string, name of the system to collect and calculate on  
            if_name:    string, interface name, 
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            interval:   timedelta object, size of the sliding window which the calculation is made on,
            frequency:  timedelta object, frequency of metric calculation,
            path:       string, path to the dataset
            attackDate: string, date of the attack the calculations are made on
    Output: dataSet:    pandas dataframe, contains the dataset       
'''
def makeDataSetRandomForestCombinedTelemetry(start, stop, systemId, bucket, fields, interval, frequency, path, attackDate):
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    isDataFrame = False
    p = Path('Telemetry')
    q = p / 'RandomForest' / 'DataSets'
    fieldsFile = str(q) + "/" + str(path) +"/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"
    if Path(fieldsFile).exists():
        with open(str(fieldsFile), 'rb') as f:
            df = np.load(f, allow_pickle=True)
        
        if len(df) == 0:
            with open(str(q) + "/" +str(path) + "/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'wb') as f:
                np.save(f, np.array([]))
            return
        timeStamps, measurements, labels = structureDataEntropyNumpyArrays(df)
    else:
        print("Cant find", fieldsFile)
        if not q.exists():
            q.mkdir(parents=True, exist_ok=False)
        df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),bucket, systemId, fields)
        isDataFrame = True
        if len(df) == 0:
            with open(str(q) + "/" +str(path) + "/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'wb') as f:
                np.save(f, np.array([]))
            return
        timeStamps, measurements = structureDataTelemetry(df)
        with open(str(fieldsFile), 'wb') as f:
            np.save(f, df)


    entropyFile =  str(q) + "/" + str(path) +"/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"
    if Path(entropyFile).exists():
        with open(str(entropyFile), 'rb') as f:
            entropy_df = pd.read_pickle(f)
    else:
        print("Cant find", entropyFile)
        if not q.exists():
            q.mkdir(parents=True, exist_ok=False)
        entropy_df = getEntropyData(startTime, stopTime, systemId,  bucket, interval, frequency)
        with open(str(entropyFile), 'wb') as f:
            entropy_df.to_pickle(f)

    if len(entropy_df) == 0:
        with open(str(q) + "/" +str(path) + "/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'wb') as f:
            np.save(f, np.array([]))
        return
    
    entropy_intervals, entropy_measurements, labels = structureDataEntropy(entropy_df)

    data = []

    now = datetime.now()

    lastYear = now.year
    lastMonth = now.month
    lastDay = now.day
    lastHour = now.hour
    lastMinute = now.minute
    counter = 0
    for timestamp in timeStamps:
        timestamp = timestamp.replace(tzinfo=None)
        curYear = timestamp.year
        curMonth = timestamp.month
        curDay = timestamp.day
        curHour = timestamp.hour
        curMinute = timestamp.minute
        
        #Check if the current timestamp is the same as the last one
        #If so, do not search through the entropy timestamp array
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

        #Find the corresponding entropy measurements for this timestamp
        entropyPacketSize_ingress = entropy_measurements[indexInTimeArray][0]
        entropyRatePacketSize_ingress = entropy_measurements[indexInTimeArray][1]
        entropyPacketSize_egress = entropy_measurements[indexInTimeArray][2]
        entropyRatePacketSize_egress = entropy_measurements[indexInTimeArray][3]
        if isDataFrame:
            curMeasurements = []
            for field in fields:
                if (systemId == "hoytek-gw2" or systemId == "narvik-gw4") and field == "egress_queue_info__0__cur_buffer_occupancy":
                    continue
                curMeasurements.append(df[field][counter])
        else:
            curMeasurements = measurements[counter]
        
        #Add a label to the measurements
        curLabel = labels[indexInTimeArray]

        newMeasurements = [entropyPacketSize_ingress, entropyRatePacketSize_ingress, entropyPacketSize_egress, entropyRatePacketSize_egress, int(curLabel)]
        times = [timeStamps[counter]]
        times.extend(curMeasurements)
        times.extend(newMeasurements)
        data.append(times)

        counter += 1
    data = np.array(data)
    with open(str(q) + "/" +str(path) + "/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'wb') as f:
        np.save(f, data)
    #return data

'''start = "2022-09-21 01:00:00"
stop = "2022-09-22 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"
interval = timedelta(minutes = 5)
frequency = timedelta(minutes = 1)
path = "Training"
attackDate = "21.09"

dataSet = makeDataSetRandomForestTelemetry(systemId, if_name, start, stop, interval, frequency, path, attackDate)
dataSet.to_pickle("Telemetry/RandomForest/Data/TrainingSet.pkl")'''