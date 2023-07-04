import pickle
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
def findAttackFlowsSYN(silkFile, start, stop, systemId, frequency, interval, attackDate):
    p = Path('Calculations')
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    #Open file to write alerts to
    attackFlows = open(str(q) + "/AttackFlows.SYN."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    attackFlows.write("sTime,eTime")
    
    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime > stopTime + frequency:
            continue
        if rec.stime < startTime:
            continue
        if isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime):
            attackFlows.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + ","+ rec.etime.strftime("%Y-%m-%dT%H:%M:%SZ"))
            
    infile.close()
    attackFlows.close()

