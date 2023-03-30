'''
How to get the flows in a file format:

    #Get syn packets with destination AS 224 in the oslo-gw:
	rwfilter --start-date=2011/01/03:00 --end-date=2011/01/10:00 --proto=6,56 --flags-all=S/SA --pass-destination=/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw
	
    #Sorts them by start time
	rwsort --fields=stime --output-path=/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in-sorted.rw  /home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in.rw 

'''

from silk import *
from datetime import datetime
from .IsAttackFlow import *

'''

    Calculates the number of SYN packets in a flow and alerts in case of an anomaly
    Input:  File with flow records sorted on time, 
            start time as a string, 
            a window size of how many flows back we should compare the values
'''

def synCalculation(silkFile, start, stop, systemId, attackDate):
    #Open file to write alerts to
    calculations = open("NetFlowCalculations/Threshold/Calculations/SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    attackFlows = open("NetFlowCalculations/Threshold/Calculations/AttackFlowsSYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #Write the column titles to the files
    calculations.write("Time,synPacketsPerFlow")
    attackFlows.write("sTime,eTime,synPacketsPerFlow")
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    synPacketsPerFlow = []
    
    #Instantiate counter variable
    i = 0

    #Loop through all the flow records
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
        synPacketsPerFlow.append(rec.packets)

        if rec.packets >= 2:
            calculations.write("\n" + str(rec.stime) + "," + str(synPacketsPerFlow[i]))
        if isAttackFlow(rec.sip, rec.dip):
            attackFlows.write("\n" + str(rec.stime) + ","+ str(rec.etime)+"," + str(synPacketsPerFlow[i]))
        i += 1
    infile.close()
'''
synCalculation("/home/linneafg/silk-data/RawDataFromFilter/one-day-tcp-syn-sorted.rw", "2011-01-10 00:00:00", "2011-01-11 00:00:00", 10)
'''