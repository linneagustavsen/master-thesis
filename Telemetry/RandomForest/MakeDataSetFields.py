from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.StructureData import structureDataTelemetry
import numpy as np

from HelperFunctionsTelemetry.GetDataTelemetry import getData

'''
    Make a dataset to use for either training or testing a Random Forest classifier
    Input:  silkFile:   string, file with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            path:       string, path to the dataset
            attackDate: string, date of the attack the calculations are made on
    Output: dataSet:    pandas dataframe, contains the dataset         
'''
def makeDataSetTelemetryFields(start, stop, bucket, fields, systemId, path, attackDate):
    p = Path('Telemetry')
    q = p / 'RandomForest' / 'DataSets' / str(path)
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    fieldsFile = str(q) +"/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"
    if not Path(fieldsFile).exists():
        print("Cant find", fieldsFile)
        startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')

        df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), bucket, systemId, fields)
        if len(df) == 0:
            with open(str(q) + "/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'wb') as f:
                np.save(f, np.array([]))
            return
        timeStamps, measurements = structureDataTelemetry(df)

        data = []

        for i in range(len(timeStamps)):
            times = [timeStamps[i]]
            times.extend(measurements[i]) 
            times.append(int(isAttack(timeStamps[i] - timedelta(seconds = 2), timeStamps[i])))

            data.append(times)
        data = np.array(data)

        if not q.exists():
            q.mkdir(parents=True, exist_ok=False)
        with open(str(q) + "/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'wb') as f:
            np.save(f, data)