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
def makeDataSetNetFlowFields(silkFile, start, stop, systemId, path, attackDate):
    p = Path('NetFlow')
    q = p / 'RandomForest' / 'RawData'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    columTitles = ["srcIP","dstIP","srcPort","dstPort","protocol","packets","bytes","fin","syn","rst","psh","ack","urg","ece","cwr","duration", "nextHopIP", "label"]   

    df = getDataNetFlow(silkFile, start, stop)
    df.to_pickle(str(q)+ "/"+path+".attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #df = pd.read_pickle(str(q)+ "/"+path+".attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    sTime, eTime, measurements = structureData(df)
    data = np.empty((len(sTime),len(columTitles)))

    for i in range(len(sTime)):
        curMeasurements = np.concatenate((measurements[i][:-1], measurements[i][-1]), axis=None)

        data[i] = curMeasurements
    dataSet = pd.DataFrame(data, columns=columTitles)
    
    return dataSet

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
def makeDataSetNoIPNetFlowFields(silkFile, start, stop, systemId, path, attackDate):
    p = Path('NetFlow')
    q = p / 'RandomForest' / 'RawData'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    columTitles = ["srcPort","dstPort","protocol","packets","bytes","fin","syn","rst","psh","ack","urg","ece","cwr","duration", "label"]    
    df = getDataNetFlow(silkFile, start, stop)
    df.to_pickle(str(q) + "/NoIP"+path+".attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #df = pd.read_pickle(str(q) + "/NoIP"+path+"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    sTime, eTime, measurements = structureData(df)
    data = np.empty((len(sTime),len(columTitles)))

    for i in range(len(sTime)):
        curMeasurements = np.concatenate((measurements[i][2:-2], measurements[i][-1]), axis=None)

        data[i] = curMeasurements
    dataSet = pd.DataFrame(data, columns=columTitles)
    return dataSet