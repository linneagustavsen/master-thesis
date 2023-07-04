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
def makeDataSetNetFlowFields(silkFile, start, stop, path, systemId, attackDate):
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    p = Path('NetFlow')
    q = p /'RandomForest'/ 'DataSets' / str(path) 

    fieldsFile = str(q) +"/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"
    if not Path(fieldsFile).exists():
        print("Cant find", fieldsFile)
        #If the systemId == ifi2-gw you have to make an empty numpy array of shape 14 319 852 rows and 20 columns and set sTime and eTime to 0 and save sTime in a separate numpy array
        data = getDataNetFlow(silkFile, startTime, stopTime)

        if not q.exists():
            q.mkdir(parents=True, exist_ok=False)
        with open(str(q) + "/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'wb') as f:
            np.save(f, data)

        if len(data) <2:
            return []
    #return data

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
def makeDataSetNoIPNetFlowFields(silkFile, start, stop, path, systemId, attackDate):  
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
        with open(str(q) + "/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'wb') as f:
            np.save(f, data)

        if len(data) <2:
            return []
    
    #return data