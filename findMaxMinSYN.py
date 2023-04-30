import json
import numpy as np
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime, timedelta
from HelperFunctions.IsAttack import *

'''
    Calculates entropy on TCP SYN packets and writes it to file
    Input:  
            silkFile:   string, file with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            attackDate: string, date of the attack the calculations are made on
'''
def synEntropyCalculation(silkFile, start, stop, frequency, interval):

    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    synSYNPerFlow = []

    maxSYN = 0
    minSYN = 1000000000000000000

    synSYNPerFlow = []
    
    #Instantiate variables
    i = 0

    #Loop through all the flow records
    for rec in infile:
        if rec.etime >= stopTime:
            continue
        if rec.stime < startTime:
            continue
        synSYNPerFlow.append(rec.packets)

        #If there is enough stored values to compare with we compare the difference of the metric with a threshold
        if i >= 10:
            change = abs(synSYNPerFlow[i] - np.nanmean(synSYNPerFlow[i-10: i-1]))
            if change > maxSYN:
                maxSYN = change
            elif change < minSYN:
                minSYN = change 
           
        i += 1
            
    infile.close()

    json_file = open("NetFlow/Entropy/Calculations/MinMax.syn."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": minSYN, "maximum": maxSYN},json_file)
    json_file.close()

synEntropyCalculation("/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/tcp-syn-all7weeks-sorted.rw", "2010-12-27 00:00:00", "2011-02-14 00:00:00", timedelta(minutes = 1), timedelta(minutes = 10))