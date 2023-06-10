from pathlib import Path
from datetime import datetime,timedelta
import pandas as pd
from HelperFunctions.StructureData import *
import numpy as np
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from HelperFunctionsTelemetry.GetDataTelemetry import *


'''
    Make a dataset to use for either testing a K-means clustering algorithm
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
def makeDataSetKmeansTelemetry(start, stop, entropy_df, systemId, bucket, fields, attackDate):
    columTitles = ["egress_queue_info__0__cur_buffer_occupancy","egress_stats__if_1sec_pkt","ingress_stats__if_1sec_pkt","egress_stats__if_1sec_octet","ingress_stats__if_1sec_octet","entropy_packet_size_ingress","entropy_rate_packet_size_ingress", "entropy_packet_size_egress", "entropy_rate_packet_size_egress"]
    if systemId =="hoytek-gw2" or systemId == "narvik-gw4":
        columTitles = ["egress_stats__if_1sec_pkt","ingress_stats__if_1sec_pkt","egress_stats__if_1sec_octet","ingress_stats__if_1sec_octet","entropy_packet_size_ingress","entropy_rate_packet_size_ingress", "entropy_packet_size_egress", "entropy_rate_packet_size_egress"]
    p = Path('Telemetry')
    dp = p / 'Kmeans' / 'DataSets'

    fieldsFile = str(dp) +"/Fields.attack."+str(attackDate)+ ".stopTime."+stop.strftime("%H.%M.%S")+ "."+str(systemId)+ ".pkl"
    if Path(fieldsFile).exists():
        with open(str(fieldsFile), 'rb') as f:
            df = pd.read_pickle(f)
    else:
        print("Cant find", fieldsFile)
        df = getData(start.strftime("%Y-%m-%dT%H:%M:%SZ"), stop.strftime("%Y-%m-%dT%H:%M:%SZ"), bucket, systemId, fields)

        if not dp.exists():
            dp.mkdir(parents=True, exist_ok=False)
        with open(str(dp) + "/Fields.attack."+str(attackDate)+ ".stopTime."+stop.strftime("%H.%M.%S")+ "."+str(systemId)+ ".pkl", 'wb') as f:
            df.to_pickle(f)
    if len(df) == 0:
        return pd.DataFrame([])

    timeStamps, measurements = structureDataTelemetry(df)
    
    entropy_intervals, entropy_measurements, labels = structureDataEntropy(entropy_df)

    data = np.empty((len(timeStamps),len(columTitles) ))

    now = datetime.now()

    lastYear = now.year
    lastMonth = now.month
    lastDay = now.day
    lastHour = now.hour
    lastMinute = now.minute
    
    for i in range(len(timeStamps)):
        timestamp = timeStamps[i].replace(tzinfo=None)
        #timestamp = datetime.utcfromtimestamp(((timeStamps[i] - np.datetime64('1970-01-01T00:00:00'))/ np.timedelta64(1, 's')))
        #timestamp = timeStamps[i]
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
        curMeasurements = measurements[i]

        newMeasurements = np.array([entropyPacketSize_ingress, entropyRatePacketSize_ingress, entropyPacketSize_egress, entropyRatePacketSize_egress])

        curMeasurements = np.concatenate((curMeasurements,newMeasurements), axis=None)

        data[i] = curMeasurements
    
    dataSet = pd.DataFrame(data, columns=columTitles)
    return dataSet