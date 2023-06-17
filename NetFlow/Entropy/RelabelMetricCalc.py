from pathlib import Path
import pandas as pd


def relabelMetricCalc(systemId, intervals, attackDate):
    p = Path('Calculations')
    q = p / 'Entropy' / 'NetFlow'

    if attackDate == "08.03.23":
        fileString = "0803"
    elif attackDate == "17.03.23":
        fileString = "1703"
    elif attackDate == "24.03.23":
        fileString = "2403"

    attackFlows = pd.read_csv("Calculations"+fileString+"/Entropy/NetFlow/AttackFlows.SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
    sTimeAttacks = pd.to_datetime(attackFlows["sTime"])
    eTimeAttacks = pd.to_datetime(attackFlows["eTime"])
   
    attackIntervals = []
    
    lastInterval = pd.Interval(pd.Timestamp.now().replace(tzinfo=None), pd.Timestamp.now().replace(tzinfo=None), closed="both")
    for i in range(len(sTimeAttacks)):
        if sTimeAttacks[i].replace(second=0).replace(tzinfo=None) in lastInterval and eTimeAttacks[i].replace(second=0).replace(tzinfo=None) in lastInterval:
            continue
        elif sTimeAttacks[i].replace(second=0).replace(tzinfo=None) in lastInterval:
            attackIntervals.remove(lastInterval)
            lastInterval = pd.Interval(lastInterval.left, eTimeAttacks[i].replace(second=0).replace(tzinfo=None), closed="both")
            attackIntervals.append(lastInterval)
        
        elif eTimeAttacks[i].replace(second=0).replace(tzinfo=None) in lastInterval:
            attackIntervals.remove(lastInterval)
            lastInterval = pd.Interval(sTimeAttacks[i].replace(second=0).replace(tzinfo=None), lastInterval.right, closed="both")
            attackIntervals.append(lastInterval)
        else:
            lastInterval = pd.Interval(sTimeAttacks[i].replace(second=0).replace(tzinfo=None), eTimeAttacks[i].replace(second=0).replace(tzinfo=None), closed="both")
            attackIntervals.append(lastInterval)

    for interval in intervals:
        print(interval)
        data = pd.read_csv("Calculations"+fileString+"/Entropy/NetFlow/SYN."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

        sTime = pd.to_datetime(data["sTime"])
        eTime = pd.to_datetime(data["eTime"])

        newLabels = []
        #Loop through all the flow records in the input file
        for i in range(len(sTime)):
            sTime[i] = sTime[i].replace(tzinfo=None)
            eTime[i] = eTime[i].replace(tzinfo=None)
            
            attack = False
            for timeInterval in attackIntervals:
                if sTime[i] in timeInterval or eTime[i] in timeInterval:
                    attack = True
            
            newLabels.append(int(attack))
        
        data["real_label"] = newLabels
        if not q.exists():
            q.mkdir(parents=True)
        data.to_csv(str(q)+ "/SYN."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", index= False)