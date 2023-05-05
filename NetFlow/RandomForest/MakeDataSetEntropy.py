from pathlib import Path
from HelperFunctions.GetData import getEntropyDataNetFlow
import numpy as np

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
def makeDataSetNetFlowEntropy(silkFile, start, stop, frequency, interval, path, systemId, attackDate):
    entropy_df = getEntropyDataNetFlow(silkFile, start, stop, frequency, interval)
    p = Path('NetFlow')
    q = p /'RandomForest'/ 'DataSets' / str(path)
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    with open(str(q) + "/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'wb') as f:
        np.save(f, entropy_df)

    if len(entropy_df) <2:
        return []
    #return entropy_df