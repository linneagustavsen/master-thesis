from pathlib import Path
from silk import *
from HelperFunctions.Distributions import *
from datetime import datetime,timedelta
from HelperFunctions.IsAttack import *

'''
    Calculates the number of ICMP destination unreachable packets in a flow and writes all values to file
    Input:  silkFile:   string, file with flow records sorted on time
            start:      string, start time of detection 
            stop:       string, stop time of detection 
            systemId:   string, name of the system to calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            attackDate: string, date of the attack the calculations are made on
'''
def icmpDstUnreachableCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate):
    p = Path('Calculations')
    q = p / 'Threshold' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    #Open file to write alerts to
    calculations = open(str(q) + "/ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    attackFlows = open(str(q) + "/AttackFlows.ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #Write the column titles to the files
    calculations.write("sTime,eTime,ICMPDstUnreachable")
    attackFlows.write("sTime,eTime,ICMPDstUnreachable")
    
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    
    #Instantiate empty arrays for the calculated values
    records = []

    numberOfIcmpDstUnreachablePackets = []

    #Instantiate variables
    i = 0
    sizes = []
   
    for rec in infile:
        if rec.etime > stopTime + frequency:
            continue
        if rec.stime < startTime:
            continue
        #Implement the sliding window
        if rec.stime > windowTime + frequency:
            lastSizes  = sum(sizes)
            thisMinuteSize = len(records) - lastSizes
            sizes.append(thisMinuteSize)
            windowTime += frequency
        if rec.stime > startTime + interval:
            #Find the number of ICMP Destination unavailable packets in this time interval
            numberOfIcmpDstUnreachablePackets.append(numberOfPackets(records))
            
            calculations.write("\n" + (rec.stime-frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(numberOfIcmpDstUnreachablePackets[i]))
            
            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1

        if isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime):
            attackFlows.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + ","+ rec.etime.strftime("%Y-%m-%dT%H:%M:%SZ"))
        records.append(rec)
        

    infile.close()
    calculations.close()
    attackFlows.close()
