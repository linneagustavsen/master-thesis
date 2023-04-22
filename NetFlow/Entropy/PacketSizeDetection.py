from matplotlib.path import Path
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import numpy as np

'''
    Calculates packet size entropy and entropy rate and alerts in case of an anomaly
    Input:  
            silkFile:                       string, file with flow records sorted on time
            start:                          string, indicating the start time of the data wanted
            stop:                           string, indicating the stop time of the data wanted
            systemId:                       string, name of the system to collect and calculate on
            frequency:                      timedelta object, frequency of metric calculation
            interval:                       timedelta object, size of the sliding window which the calculation is made on
            windowSize:                     int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdPSEntropy:             float, values over this threshold will cause an alert
            thresholdPSEntropyRate:         float, values over this threshold will cause an alert
            attackDate:                     string, date of the attack the calculations are made on
'''
def detectionPS(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdPSEntropy, thresholdPSEntropyRate, attackDate):
    p = Path('Detections')
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    #Open files to write alerts to
    packetSizeEntropyFile = open(str(q) + "/PacketSizeEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    packetSizeEntropyRateFile = open(str(q) + "/PacketSizeEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    packetSizeEntropyFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    packetSizeEntropyRateFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    
    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []

    packetSizeArray = []
    packetSizeRateArray = []
    
    #Instantiate variables
    i = 0
    sizes = []

    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
        #Implement the sliding window
        if rec.stime > windowTime + frequency:
            lastSizes  = sum(sizes)
            thisMinuteSize = len(records) - lastSizes
            sizes.append(thisMinuteSize)
            windowTime += frequency
        #Aggregate flows into the specified time interval
        if rec.stime > startTime + interval:
            if len(records) == 0:
                startTime = startTime + frequency
                sizes.pop(0)
                records.append(rec)
                continue
            #Find the probability distribution based on how big the packets are this time interval
            PiPS,nps = packetSizeDistributionNetFlow(records)
            #Calculate the generalized entropy of this distribution
            entropyPacketSize = generalizedEntropy(10, PiPS)
            packetSizeArray.append(entropyPacketSize)
            #Calculate the generalized entropy rate of this distribution
            packetSizeRateArray.append(entropyPacketSize/nps)

            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                if abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1])) > thresholdPSEntropy:
                    packetSizeEntropyFile.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1]))) + "," + str(packetSizeArray[i]) + "," + str(np.nanmean(packetSizeArray[i-windowSize: i-1])))
                
                if abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1])) > thresholdPSEntropyRate:
                    packetSizeEntropyRateFile.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1]))) + "," + str(packetSizeRateArray[i]) + "," + str(np.nanmean(packetSizeRateArray[i-windowSize: i-1])))
                 
            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1

        records.append(rec)
    
    packetSizeEntropyFile.close()
    packetSizeEntropyRateFile.close()

    infile.close()
    