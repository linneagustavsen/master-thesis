import pickle
import pandas as pd
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime
from HelperFunctions.IsAttack import *
from pathlib import Path

'''
    Calculates entropy and other metrics and write them to file. Also checks if the flow is an attack flow
    Input:  
            silkFile:   string, file with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            attackDate: string, date of the attack the calculations are made on
'''
def metricCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate):
    #Open files to write alerts to
    p = Path('Calculations')
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)

    packetSizeDistributionDict ={}
    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime
    starting = startTime
    pushed = False

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []
    
    #Instantiate variables
    i = 0
    sizes = []
    attackFlowArray = []

    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime > stopTime + frequency:
            continue
        if rec.stime < startTime:
            continue
        if rec.stime >= starting and not pushed:
            startTime = rec.stime.replace(microsecond = 0, second = 0)
            pushed = True
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
            
            #Make dictionary for how many packets each packet size has
            numberOfPacketsOfSizei = {}
            
            #Loop through the flow records
            for rec in records:
                #If there are no packets the size is 0
                if rec.packets == 0:
                    size = 0
                else:
                    #If there are packets the average size of a packet is calculated for this measurement, cast to an integer, and stored
                    size = int(rec.bytes/rec.packets)
                #If the size of the packet has been encountered before the number of packets with this size is increased by the number of packets
                if size in numberOfPacketsOfSizei:
                    numberOfPacketsOfSizei[size] += rec.packets
                else:
                    numberOfPacketsOfSizei[size] = rec.packets

            if i == 0:
                timeInterval = pd.Interval(pd.Timestamp(startTime), pd.Timestamp(rec.stime.replace(microsecond = 0, second = 0)), closed="both")
            else:
                timeInterval = pd.Interval(pd.Timestamp(rec.stime.replace(microsecond = 0, second = 0) - frequency), pd.Timestamp(rec.stime.replace(microsecond = 0, second = 0)), closed="right")

            packetSizeDistributionDict[timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ")] = numberOfPacketsOfSizei

            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
        records.append(rec)

    infile.close()
    
    json_file = open(str(q) + "/packetSizeDistributions."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", "wb")
    pickle.dump(packetSizeDistributionDict,json_file)
    json_file.close()
