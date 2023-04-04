from silk import *
from HelperFunctions.Distributions import *
from datetime import datetime,timedelta
from HelperFunctions.IsAttack import *

'''
    Calculates the number of ICMP destination unreachable packets in a flow and writes all values to file
    Input:  silkFile:   string, File with flow records sorted on time
            start:      string, start time of detection 
            stop:       string, stop time of detection 
            systemId:   string, name of the system to calculate on
            frequency:  timedelta object, frequency of metric calculation
            attackDate: string, date of the attack the calculations are made on
'''
def icmpDstUnreachableCalculation(silkFile, start, stop, systemId, frequency, attackDate):
    #Open file to write alerts to
    calculations = open("Calculations/Threshold/NetFlow/ICMPDstUnreachable.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    attackFlows = open("Calculations/Threshold/NetFlow/AttackFlowsICMPDstUnreachable.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #Write the column titles to the files
    calculations.write("Time,ICMPDstUnreachable")
    attackFlows.write("sTime,eTime,ICMPDstUnreachable")
    
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    
    #Instantiate empty arrays for the calculated values
    records = []

    numberOfIcmpDstUnreachablePackets = []

    #Instantiate counter variable
    i = 0
   
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
        if rec.stime >= startTime + frequency:
            
            #Find the number of ICMP Destination unavailable packets in this time frequency
            numberOfIcmpDstUnreachablePackets.append(numberOfPackets(records))
            
            calculations.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(numberOfIcmpDstUnreachablePackets[i]))
            #Reset the record aggregation
            records = []
            startTime = startTime + frequency
            i += 1

        if isAttackFlow(rec.sip, rec.dip):
            attackFlows.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + ","+ rec.etime.strftime("%Y-%m-%dT%H:%M:%SZ") + str(numberOfIcmpDstUnreachablePackets[i]))
        records.append(rec)
        

    infile.close()
    calculations.close()
    attackFlows.close()