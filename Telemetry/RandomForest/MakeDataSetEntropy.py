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
    q = p /'RandomForest'/ 'DataSets' / str(path) 

    entropyFile = str(q) +"/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"
    if not Path(entropyFile).exists():
        print("Cant find", entropyFile)

        startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
        entropy_df = getEntropyData(startTime, stopTime, systemId, bucket, interval, frequency)

        if not q.exists():
            q.mkdir(parents=True, exist_ok=False)
        with open(str(q) + "/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", 'wb') as f:
            entropy_df.to_pickle(f)