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
            path:       string, path to the dataset
            attackDate: string, date of the attack the calculations are made on
    Output: dataSet:    pandas dataframe, contains the dataset         
'''
def makeTestingDataSetNetFlowFields(silkFile, start, stop, path, systemId, attackDate):
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    p = Path('NetFlow')
    q = p /'RandomForest'/ 'DataSets' / str(path) 
    
    for i in range(1,9):
        if startTime + timedelta(minutes=30) < stopTime:
            stopping = startTime + timedelta(minutes=30)
        else:
            stopping = stopTime

        fieldsFile = str(q) +"/Fields.attack."+str(attackDate)+ "."+str(systemId)+ "." + str(i)+".npy"
        if not Path(fieldsFile).exists():
            print("Cant find", fieldsFile)
            data = getDataNetFlow(silkFile, startTime, stopping)

            if not q.exists():
                q.mkdir(parents=True, exist_ok=False)
            with open(str(q) + "/Fields.attack."+str(attackDate)+ "."+str(systemId)+ "." + str(i)+".npy", 'wb') as f:
                np.save(f, data)
        startTime += timedelta(minutes=30)     

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
def makeTestingDataSetNoIPNetFlowFields(silkFile, start, stop, path, systemId, attackDate):  
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    p = Path('NetFlow')
    q = p /'RandomForest'/ 'DataSets' / str(path) 

    fieldsFile = str(q) +"/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"
    if not Path(fieldsFile).exists():
        print("Cant find", fieldsFile)
        data = getDataNetFlow(silkFile, startTime, stopTime)

        if not q.exists():
            q.mkdir(parents=True, exist_ok=False)
        for i in range(1,10):
            with open(str(q) + "/Fields.attack."+str(attackDate)+ "."+str(systemId)+ "." + str(i)+".npy", 'wb') as f:
                np.save(f, data)
            
        if len(data) <2:
            return
    
    #return data