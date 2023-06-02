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
def findAttackFlowsICMPdstUnreachable(silkFile, start, stop, systemId, frequency, interval, attackDate):
    p = Path('Calculations')
    q = p / 'Threshold' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    #Open file to write alerts to
    attackFlows = open(str(q) + "/AttackFlows.ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #Write the column titles to the files
    attackFlows.write("sTime,eTime")
    
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    
   
    for rec in infile:
        if rec.etime > stopTime + frequency:
            continue
        if rec.stime < startTime:
            continue
        
        if isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime):
            attackFlows.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + ","+ rec.etime.strftime("%Y-%m-%dT%H:%M:%SZ"))
        
    infile.close()
    attackFlows.close()
