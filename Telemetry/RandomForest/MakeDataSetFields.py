from datetime import timedelta
from pathlib import Path
from HelperFunctions.GetData import getData
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
def makeDataSetTelemetryFields(start, stop, bucket, systemId, path, attackDate):
    p = Path('Telemetry')
    q = p / 'RandomForest' / 'RawData'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    columTitles = ["egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkt", "ingress_stats__if_1sec_pkt", "egress_stats__if_1sec_octet", "ingress_stats__if_1sec_octet", "label"]   

    df = getData(start, stop, bucket, systemId, columTitles[:-1])
    df.to_pickle(str(q)+ "/"+path+".attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    timeStamps, measurements = structureDataTelemetry(df)
    data = np.empty((len(timeStamps),len(columTitles)))

    for i in range(len(timeStamps)):
        curMeasurements = np.concatenate((measurements[i], int(isAttack(timeStamps[i] - timedelta(seconds = 2), timeStamps[i]))), axis=None)

        data[i] = curMeasurements
    
    return data