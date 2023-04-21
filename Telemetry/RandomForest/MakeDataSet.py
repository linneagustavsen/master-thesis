from pathlib import Path
from HelperFunctions.IsAttack import isAttack
from HelperFunctionsTelemetry.GetDataTelemetry import *
from datetime import datetime,timedelta
import pandas as pd
from HelperFunctions.StructureData import *
import numpy as np
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from .CheckLabel import *

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
def makeDataSetRandomForestTelemetry(systemId, if_name, start, stop, interval, frequency, path, attackDate):
    columTitles = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets","entropy_packet_size", "entropy_rate_packet_size", "label"]
    
    fields = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets"]

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), systemId, if_name, fields)

    p = Path('Telemetry')
    q = p / 'RandomForest' / 'RawData'
    if not q.exists():
        q.mkdir(parents=True)
    df.to_pickle(str(q) + "/"+path+"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #df = pd.read_pickle(str(q) + "/"+path+"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    timeStamps, measurements = structureDataTelemetry(df)

    entropy_df = getEntropyData(startTime, stopTime, systemId, if_name, interval, frequency)
    entropy_df.to_pickle(str(q) + "/"+path+".Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #entropy_df = pd.read_pickle(str(q) + "/"+path+".Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")  
    entropy_timeStamps, entropy_measurements = structureDataTelemetry(entropy_df)

    data = np.empty((len(timeStamps),len(columTitles)))

    now = datetime.now()

    lastYear = now.year
    lastMonth = now.month
    lastDay = now.day
    lastHour = now.hour
    lastMinute = now.minute
    
    for i in range(len(timeStamps)):
        timestamp = timeStamps[i]
        curYear = timestamp.year
        curMonth = timestamp.month
        curDay = timestamp.day
        curHour = timestamp.hour
        curMinute = timestamp.minute
        
        #Check if the current timestamp is the same as the last one
        #If so, do not search through the entropy timestamp array
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

        #Find the corresponding entropy measurements for this timestamp
        entropyPacketSize = entropy_measurements[indexInTimeArray][0]
        entropyRatePacketSize = entropy_measurements[indexInTimeArray][1]
        curMeasurements = measurements[i]
        
        #Add a label to the measurements
        curLabel = isAttack(timestamp- timedelta(seconds = 2), timestamp)

        newMeasurements = np.array([entropyPacketSize, entropyRatePacketSize, int(curLabel)])

        curMeasurements = np.concatenate((curMeasurements,newMeasurements), axis=None)

        data[i] = curMeasurements
    
    dataSet = pd.DataFrame(data, columns=columTitles)
    return dataSet

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