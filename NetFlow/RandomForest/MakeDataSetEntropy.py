from HelperFunctions.GetData import *
from datetime import datetime
import pandas as pd
from HelperFunctions.StructureData import *
import numpy as np

'''
    Make a dataset to use for either training or testing a Random Forest classifier
    Input:  silkFile:   string, File with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            path:       string, path to the dataset
            attackDate: string, date of the attack the calculations are made on
    Output: dataSet:    pandas dataframe, contains the dataset         
'''
def makeDataSetNetFlowEntropy(silkFile, start, stop, systemId, frequency, interval, path, attackDate):
    columTitles = ["entropy_ip_source","entropy_rate_ip_source","entropy_ip_destination","entropy_rate_ip_destination","entropy_flow","entropy_rate_flow","number_of_flows","icmp_ratio","number_of_icmp_packets","packet_size_entropy","packet_size_entropy_rate","number_of_packets","number_of_bytes", "label"]   

    entropy_df = getEntropyDataNetFlow(silkFile, start, stop, frequency, interval)
    entropy_df.to_pickle("NetFlow/RandomForest/RawData/"+path+".Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #entropy_df = pd.read_pickle("NetFlow/RandomForest/RawData/"+path+"Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")   
    entropy_timeStamps, entropy_measurements = structureDataEntropy(entropy_df)

    data = np.empty((len(entropy_timeStamps),len(columTitles)))
    
    for i in range(len(entropy_timeStamps)):
        curMeasurements = np.concatenate((entropy_measurements[i],isAttack(entropy_timeStamps[i])), axis=None)

        data[i] = curMeasurements
    dataSet = pd.DataFrame(data, columns=columTitles)
    return dataSet