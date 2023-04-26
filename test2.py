'''from datetime import timedelta
from NetFlow.TopKFlows.topkflow import topkflows, topkflows2 
from HelperFunctions.GeneralizedEntropy import generalizedEntropy
start="2011-01-19 06:56:00"
stop="2011-01-19 08:37:00"
interval = timedelta(minutes = 1)
silkFile = "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/dip-in-destination-ips-sorted.rw"
topkflows2(silkFile, start, stop, interval, 20, "19.01", "oslo-gw")
'''
'''import math
def generalizedEntropy(alpha, Pi):
    sumProb = 0
    for pi in Pi:
        sumProb += pi**alpha

    return 1/(1-alpha)*math.log(sumProb, 2)

def generalizedEntropy2(alpha, Pi):
    sumProb = 0
    for pi in Pi:
        sumProb += pi**alpha

    fraction = 1/(1-alpha)

    return fraction*math.log(sumProb, 2)
Pi = [0.1, 0.3, 0.1, 0.2, 0.3]
print(generalizedEntropy(10, Pi))
print(generalizedEntropy2(10, Pi))'''


from datetime import timedelta, datetime
import math
from time import sleep
'''baseFile="two-hours-2011-02-08_10-12-sorted.rw"         
systems = ["oslo-gw"]
start = "2011-02-08 10:00:00"
stop = "2011-02-08 12:00:00"
startCombined = "2011-02-08 10:00:00"
stopCombined = "2011-02-08 12:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 10)
pathToRawFiles="/home/linneafg/silk-data/RawDataFromFilter/"
attackDate="08.02.11"
systemId =  "oslo-gw"
silkFileSyn = pathToRawFiles+systemId + "/tcp-syn-"+ baseFile
synDetection(silkFileSyn, start, stop, systemId, 10, 2, attackDate)'''

'''start = ['2022-09-22 00:00:00', '2023-01-25 00:00:00']
stop = ['2022-10-22 00:00:00', '2023-02-23 00:00:00']
startTime = datetime.strptime(start[0], '%Y-%m-%d %H:%M:%S')
stopTime = datetime.strptime(stop[0], '%Y-%m-%d %H:%M:%S')
intervalTime = (stopTime - startTime).total_seconds()/86400
print(math.ceil(intervalTime))'''
'''
def priority_getter(value):
    print("\n")
    print(value)
    priority = {
        "Flooding": 0,
        "SYN Flood": 1,
        "Same protocol": 2,
        "Low-Rate": 3,
        "Different protocols": 4,
        None: 5
    }
    highestKey = max(value["Attack_type"], key= lambda x: value["Attack_type"][x])
    print(highestKey)
    if highestKey == None:
        newValue = dict((i,value["Attack_type"][i]) for i in value["Attack_type"] if i!=None)
        highestKey = max(newValue, key= lambda x: newValue[x])
    print(highestKey)
    return priority.get(highestKey)


alert = {
                "Attack_type": {'Low-Rate': 1},
                "Deviation_score": 2
            }
alert2 = {
                "Attack_type": {"SYN Flood": 2, None:100},
                "Deviation_score": 1
            }
alert3 = {
                "Attack_type": {"Flooding":3, "Low-Rate":100},
                "Deviation_score": 5
            }
alert4 = {
                "Attack_type": {"Flooding":101, "Low-Rate":100},
                "Deviation_score": 3
            }
alert5 = {
                "Attack_type": {None:1000, "Low-Rate":100},
                "Deviation_score": 3
            }
values = [alert, alert2, alert3, alert4, alert5]
values = sorted(values, key=lambda x: x["Deviation_score"], reverse=True)
print(values)
print(sorted(values, key=priority_getter))

[{  
    'Attack_type': 
        {'Flooding': 101, 'Low-Rate': 100}, 
    'Deviation_score': 3}, 
{   
    'Attack_type': 
        {'SYN Flood': 2, None: 100}, 
    'Deviation_score': 1}, 
{   
    'Attack_type': 
        {'Flooding': 3, 'Low-Rate': 100}, 
    'Deviation_score': 5}, 
{   
    'Attack_type': 
        {None: 1000, 'Low-Rate': 100}, 
    'Deviation_score': 3}, 
{   
    'Attack_type': 
        {'Low-Rate': 1},
    'Deviation_score': 2
    
}]

values = [ 1, 2, 3, 4, 5, 6, 7, 8, 9]

value1 = [ 1, 2, 3, 4, 5]
value2 = [ 2, 3, 4, 5, 6]
value3 = [ 3, 4, 5, 6, 7]
value4 = [ 4, 5, 6, 7, 8]
value5 = [ 5, 6, 7, 8, 9]
''''''
alert = {
                "Attack_type": '',
                "Deviation_score": 2
            }

print(type(alert["Attack_type"]))'''

stime = datetime(2011,1,2,14,30)
now = datetime.now()
print(stime, now.replace(year=2011, month=1, day=2))
print((now.replace(year=2011, month=1, day=2) - stime).total_seconds())

def simulateRealTime(timeNow, stime, attackDate):
    attackDate = attackDate.split(".")
    attackYear = 2000 + int(attackDate[2])
    attackMonth = int(attackDate[1])
    attackDay = int(attackDate[0])
    if stime > timeNow:
        duration = math.ceil((stime- timeNow.replace(year=attackYear, month=attackMonth, day=attackDay)).total_seconds())
    else:
        duration = 0
    sleep(duration)

attackDate = "08.02.11"
print(simulateRealTime(datetime.now(), stime, attackDate))