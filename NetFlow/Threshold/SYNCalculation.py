from silk import *
from datetime import datetime
from HelperFunctions.IsAttack import *

'''
    Calculates the number of SYN packets in a flow and writes all values over 1 to file
    Input:  silkFile:   string, file with flow records sorted on time
            start:      string, start time of detection 
            stop:       string, stop time of detection 
            systemId:   string, name of the system to calculate on
            attackDate: string, date of the attack the calculations are made on
'''
def synCalculation(silkFile, start, stop, systemId, attackDate):
    #Open file to write alerts to
    calculations = open("Calculations/Threshold/NetFlow/SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    attackFlows = open("Calculations/Threshold/NetFlow/AttackFlows.SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #Write the column titles to the files
    calculations.write("Time,synPacketsPerFlow")
    attackFlows.write("sTime,eTime,synPacketsPerFlow")
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

        if rec.packets >= 2:
            calculations.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(synPacketsPerFlow[i]))
        if isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime):
            attackFlows.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + ","+ rec.etime.strftime("%Y-%m-%dT%H:%M:%SZ")+"," + str(synPacketsPerFlow[i]))
        i += 1
    infile.close()