from silk import *
from datetime import datetime
import numpy as np

'''
    Calculates the number of SYN packets in a flow and alerts in case of an anomaly
    Input:  silkFile:   string, file with flow records sorted on time
            start:      string, start time of detection 
            stop:       string, stop time of detection 
            systemId:   string, name of the system to calculate on
            windowSize: int, represents a multiplier of frequency, how far back we want to compare the value with
            threshold:  int, values over this threshold will cause an alert
            attackDate: string, date of the attack the calculations are made on
'''
def synDetection(silkFile, start, stop, systemId, windowSize, threshold, attackDate):
    #Open file to write alerts to
    f = open("Detections/Threshold/NetFlow/SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #Write the column titles to the files
    f.write("Time,Change,Value,Mean_last_"+ str(windowSize))

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    synPacketsPerFlow = []
    
    #Instantiate variables
    i = 0

    #Loop through all the flow records
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
        synPacketsPerFlow.append(rec.packets)

        #If there is enough stored values to compare with we compare the difference of the metric with a threshold
        if i >= windowSize:
            if rec.packets >= threshold:
                f.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(synPacketsPerFlow[i] - np.nanmean(synPacketsPerFlow[i-windowSize: i-1]))) + "," + str(synPacketsPerFlow[i]) + "," + str(np.nanmean(synPacketsPerFlow[i-windowSize: i-1])))
        i += 1
    infile.close()