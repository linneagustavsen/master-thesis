from pathlib import Path
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
def synEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate):
    p = Path('Calculations')
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    #Open file to write alerts to
    calculations = open(str(q) + "/SYN."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    attackFlows = open(str(q) + "/NetFlow/AttackFlows.SYN."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    calculations.write("Time,srcEntropy,dstEntropy,flowEntropy")
    attackFlows.write("sTime,eTime")
    
    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime
    
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []
    entropyOfSynPacketsPerSrc = []
    entropyOfSynPacketsPerDst = []
    entropyOfSynPacketsPerFlow = []

    i = 0
    sizes = []
    lastMinuteSize = 0
    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
        #Implement the sliding window
        if rec.stime > windowTime + frequency:
            lastSizes = 0
            for size in sizes:
                lastSizes += size
            thisMinuteSize = len(records) - lastSizes
            sizes.append(thisMinuteSize)
            windowTime += frequency
        #Aggregate flows into the specified time interval
        if rec.stime > startTime + interval:
            if len(records) == 0:
                startTime = startTime + frequency
                sizes.pop(0)
                i += 1
                records.append(rec)
                continue
            #Find the probability distribution based on how many SYN packets there is in each source flow in this time interval
            PiSIP, ns = ipSourceDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropySip = generalizedEntropy(10,PiSIP)
            entropyOfSynPacketsPerSrc.append(entropySip)

            #Find the probability distribution based on how many SYN packets there is in each destination flow in this time interval
            PiDIP, nd = ipDestinationDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyDip = generalizedEntropy(10,PiDIP)
            entropyOfSynPacketsPerDst.append(entropyDip)

            #Find the probability distribution based on how many SYN packets there is in each bi-directional flow in this time interval
            PiF, nf = uniDirFlowDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyFlow = generalizedEntropy(10,PiF)
            entropyOfSynPacketsPerFlow.append(entropyFlow)
            
            calculations.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(entropyOfSynPacketsPerSrc[i]) 
                            + "," + str(entropyOfSynPacketsPerDst[i]) + "," + str(entropyOfSynPacketsPerFlow[i]))
            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
        if isAttackFlow(rec.sip, rec.dip):
            attackFlows.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + ","+ rec.etime.strftime("%Y-%m-%dT%H:%M:%SZ"))

        records.append(rec)
            

    infile.close()
    calculations.close()
    attackFlows.close()