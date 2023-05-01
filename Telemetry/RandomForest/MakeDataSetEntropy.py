from pathlib import Path
from datetime import datetime
import pandas as pd
from HelperFunctions.StructureData import *
import numpy as np
from HelperFunctions.IsAttack import *
from HelperFunctionsTelemetry.GetDataTelemetry import getEntropyData

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
def makeDataSetTelemetryEntropy(start, stop, systemId, bucket, frequency, interval, path, attackDate):
    p = Path('Telemetry')
    q = p / 'RandomForest' / 'RawData'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    columTitles = ["packet_size_entropy","packet_size_entropy_rate", "label"]   

    entropy_df = getEntropyData(start, stop, systemId, interval, frequency)
    entropy_df.to_pickle(str(q) + "/"+path+".Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    entropy_timeStamps, entropy_measurements = structureDataTelemetry(entropy_df)
    entropy_timeStamps = pd.to_datetime(entropy_timeStamps)
    
    data = np.empty((len(entropy_timeStamps),len(columTitles)))
    
    for i in range(len(entropy_timeStamps)):
        curMeasurements = np.concatenate((entropy_measurements[i],isAttack(entropy_timeStamps[i]- frequency, entropy_timeStamps[i])), axis=None)

        data[i] = curMeasurements
    return data