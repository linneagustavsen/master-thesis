'''
How to get the flows in a file format:

	#Get icmp packets with type "destination unreachable"
	rwfilter --start-date=2011/01/03:00 --end-date=2011/01/10:00 --proto=1,58 --icmp-type=3 --pass-destination=/home/linneafg/silk-data/RawDataFromFilter/icmp3-in.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw

    #Sorts them by start time
    rwsort --fields=stime --output-path=/home/linneafg/silk-data/RawDataFromFilter/icmp3-in-sorted.rw /home/linneafg/silk-data/RawDataFromFilter/icmp3-in.rw

'''

from silk import *
from HelperFunctions.Distributions import *
from datetime import datetime,timedelta
from .IsAttackFlow import *

'''

    Calculates the number of ICMP destination unreachable packets and alerts in case of an anomaly
    Input:  File with flow records sorted on time, 
            start time as a string, 
            a aggregation frequency as a timedelta object, 
            a window size of how far back we should compare the values
'''

def icmpDstUnreachableCalculation(silkFile, start, stop, systemId, frequency, attackDate):
    #Open file to write alerts to
    calculations = open("NetFlowCalculations/Threshold/Calculations/ICMPDstUnreachable.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    attackFlows = open("NetFlowCalculations/Threshold/Calculations/AttackFlowsICMPDstUnreachable.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #Write the column titles to the files
    calculations.write("Time, ICMPDstUnreachable")
    attackFlows.write("sTime, eTime")
    
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
            
            calculations.write("\n" + str(startTime) + "," + str(numberOfIcmpDstUnreachablePackets[i]))
            #Reset the record aggregation
            records = []
            startTime = startTime + frequency
            i += 1

        if isAttackFlow(rec.sip, rec.dip):
            attackFlows.write("\n" + str(rec.stime) + ","+ str(rec.etime))
        records.append(rec)
        

    infile.close()
    calculations.close()
    attackFlows.close()

'''
icmpDstUnreachableCalculation("/home/linneafg/silk-data/RawDataFromFilter/one-day-icmp3-sorted.rw", "2011-01-10 00:00:00", "2011-01-11 00:00:00", timedelta(minutes = 1), 10)'''