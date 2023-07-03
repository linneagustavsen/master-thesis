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
from pprint import pprint
from time import sleep

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix

from HelperFunctionsTelemetry.GetDataTelemetry import getData, getDataBytes
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
'''
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
print(#simulateRealTime(datetime.now(), stime, attackDate))'''

'''curMeasurements = [2360456726, 3218895927, 53533, 46975, 6, 1, 1500, 0, 0, 0, 0, 1, 0, 0, 0, 0.0, 0]
      
newMeasurements = [5.991120021222172, 6.363242439058301e-05, 5.1317477208111, 0.0002481142832669874, 6.369418930049736, 4.8367496886958085e-05, 2.1297057992113126, 0.0014419132019033937, 0]
       
times = [datetime(2011, 1, 3, 8, 0), datetime(2011, 1, 3, 8, 0)]
        
times.extend(curMeasurements)
print(times)
times.extend(newMeasurements)
print(times)
data = [times, times, times, times,times]'''
'''test1 = np.array([[1,2,3,4,10],
 [5,6,7,8,10],
 [9,10,11,12,10],
 [13,14,15,16,10],
 [17,18,19,20,10]])
print(test1)
print(test1.ndim)
test2 =np.delete(test1, np.s_[2:4],1)
print(test2)'''
'''print(confusion_matrix([0,1,0,1],[1,1,1,0]))
tn, fp, fn, tp = confusion_matrix([0,1,0,1],[1,1,1,0]).ravel()
print(tn, fp, fn, tp)'''
'''

with open("Telemetry/Kmeans/DataSets/Fields.attack.08.03.23.stopTime.15.30.00.narvik-gw3.pkl", 'rb') as f:
    df = pd.read_pickle(f)
print(df)'''

'''from Correlation.NetworkGraph import NetworkGraph
import networkx as nx
graph = NetworkGraph().G
print(nx.shortest_path(graph, "teknobyen-gw1", "hovedbygget-gw"))
'''
'''
def sortByAttackType(values):
        def priority_getter(value):
            priority = {
                "Flooding": 1,
                "ICMP Flood": 2,
                "SYN Flood": 3,
                "Same protocol": 4,
                "Xmas": 5,
                "Low-Rate": 6,
                "Different protocols": 7, 
                "": 8
            }
            print(value["Attack_types"])
            highestKey = max(value["Attack_types"], key= lambda x: value["Attack_types"][x])
            print(highestKey)

            if highestKey == "" and len(value["Attack_types"]) > 1:
                newValue = dict((i,value["Attack_types"][i]) for i in value["Attack_types"] if i!="")
                highestKey = max(newValue, key= lambda x: newValue[x])
            
            return priority.get(highestKey)

        return sorted(values, key=priority_getter)

ranking = [{
    "sTime":"2023-03-24T14:22:00Z",
    "eTime":"2023-03-24T14:23:00Z",
    "Gateways":['bergen-gw3', 'teknobyen-gw1', 'ifi2-gw5', 'hoytek-gw2', 'trd-gw'],
    "Deviation_score": {'mean': 22.568717936736192, 'standard_deviation': 155.0429322555615},
    "Attack_types":{'': 0.009670199232233789, 'Flooding': 0.01367278303735923, 'SYN Flood': 0.012525402182923332, 'Same protocol': 0.005475048217030808, 'Low-Rate': 0.0036577389046563947, 'ICMP Flood': 0.0034156030785089664},
    "Real_labels": {'0': 64265, '1': 103}
},{
    "sTime":"2023-03-24T14:24:00Z",
    "eTime":"2023-03-24T14:25:00Z",
    "Gateways": ['bergen-gw3', 'teknobyen-gw1', 'ifi2-gw5', 'hoytek-gw2', 'trd-gw'],
    "Deviation_score":{'mean': 16.839415297044592, 'standard_deviation': 125.36113598135398},
    "Attack_types":{'': 0.014741887933250078, 'Flooding': 0.012717929829492736, 'SYN Flood': 0.0063416564398198864, 'Same protocol': 0.005475048217030808, 'ICMP Flood': 0.0025883154231358223, 'Low-Rate': 0.002304020159633303},
    "Real_labels": {'0': 60209, '1': 128}},
{
"sTime":"2023-03-24T14:28:00Z",
"eTime":"2023-03-24T14:29:00Z", 
 "Gateways": ['bergen-gw3', 'teknobyen-gw1', 'ifi2-gw5', 'hoytek-gw2', 'trd-gw'],
"Deviation_score":{'mean': 13.689182343184811, 'standard_deviation': 27.338602678758757},
"Attack_types":{'': 0.0034491209338524164, 'Flooding': 0.012478323384723817, 'Different protocols': 0.005475048217030808, 'ICMP Flood': 0.0015899248017060066, 'SYN Flood': 0.009988102358061395, 'Same protocol': 0.0016874466747890684},
"Real_labels": {'0': 53498, '1': 107}
},
{
"sTime":"2023-03-24T14:21:00Z",
"eTime":"2023-03-24T14:22:00Z", 
 "Gateways": ['bergen-gw3', 'teknobyen-gw1', 'ifi2-gw5', 'hoytek-gw2', 'trd-gw'],
"Deviation_score":{'mean': 12.39116594130785, 'standard_deviation': 24.12765670820379},
"Attack_types":{'': 0.01181841671268437, 'Flooding': 0.014307971033153514, 'Same protocol': 0.005475048217030808, 'Low-Rate': 0.0020990603599299242, 'SYN Flood': 0.011685559564309892},
"Real_labels": {'0': 53628, '1': 105}
},
{
"sTime":"2023-03-24T14:20:00Z",
"eTime":"2023-03-24T14:21:00Z", 
 "Gateways": ['bergen-gw3', 'teknobyen-gw1', 'ifi2-gw5', 'hoytek-gw2', 'trd-gw'],
"Deviation_score":{'mean': 5.154965039999314, 'standard_deviation': 14.599259109906416},
"Attack_types":{'': 0.008230431143141604, 'Flooding': 0.015616922703882256, 'Different protocols': 0.0013624524143458223, 'Same protocol': 0.005475048217030808, 'SYN Flood': 0.003225408614428465},
"Real_labels": {'0': 50587, '1': 111}
},
{
"sTime":"2023-03-24T14:23:00Z",
"eTime":"2023-03-24T14:24:00Z", 
 "Gateways": ['trd-gw', 'bergen-gw3', 'hoytek-gw2'],
"Deviation_score":{'mean': 1.6147775254458736, 'standard_deviation': 7.382082379283247},
"Attack_types":{'': 0.011646288192950622, 'Flooding': 0.011756269417003836, 'SYN Flood': 0.00109572318865842, 'Same protocol': 0.0068251172301433},
"Real_labels": {'0': 34337, '1': 62}
},
{
"sTime":"2023-03-24T14:17:00Z",
"eTime":"2023-03-24T14:18:00Z", 
 "Gateways": ['bergen-gw3', 'teknobyen-gw1', 'ifi2-gw5', 'hoytek-gw2', 'trd-gw'],
"Deviation_score":{'mean': 24.099897359166974, 'standard_deviation': 30.540518963050918},
"Attack_types":{'': 0.004661182285360513, 'Flooding': 0.003582061717703524, 'SYN Flood': 0.023805590529526775},
"Real_labels": {'0': 73110, '1': 107}
},
{
"sTime":"2023-03-24T14:27:00Z",
"eTime":"2023-03-24T14:28:00Z", 
 "Gateways": ['bergen-gw3', 'teknobyen-gw1', 'ifi2-gw5', 'hoytek-gw2', 'trd-gw'],
"Deviation_score":{'mean': 14.222587954536554, 'standard_deviation': 23.790469413398696},
"Attack_types":{'': 0.005135768152872067, 'Flooding': 0.011257212178899955, 'SYN Flood': 0.01396810463084144, 'Same protocol': 0.0013495276653171385, 'ICMP Flood': 0.0018589533585846342},
"Real_labels": {'0': 51691, '1': 109}
},
{
"sTime":"2023-03-24T14:22:00Z",
"eTime":"2023-03-24T14:23:00Z", 
 "Gateways": ['bergen-gw3', 'trd-gw'],
"Deviation_score":{'mean': 4.651106604098997, 'standard_deviation': 3.1046617484560888},
"Attack_types":{'Same protocol': 0.013482106596085602},
"Real_labels": {'1': 15}
},
{
"sTime":"2023-03-24T14:22:00Z",
"eTime":"2023-03-24T14:23:00Z", 
 "Gateways": ['bergen-gw3', 'trd-gw'],
"Deviation_score":{'mean': 4.636656902242457, 'standard_deviation': 3.1241435031281775},
"Attack_types":{'Same protocol': 0.016173764876483955},
"Real_labels": {'1': 18}
},
{
"sTime":"2023-03-24T14:23:00Z",
"eTime":"2023-03-24T14:24:00Z", 
 "Gateways": ['bergen-gw3', 'trd-gw'],
"Deviation_score":{'mean': 4.5894100097161505, 'standard_deviation': 3.1870613022168364},
"Attack_types":{'Same protocol': 0.013482106596085602},
"Real_labels": {'1': 15}
},
{
"sTime":"2023-03-24T14:23:00Z",
"eTime":"2023-03-24T14:24:00Z", 
 "Gateways": ['bergen-gw3', 'trd-gw'],
"Deviation_score":{'mean': 4.583124702562137, 'standard_deviation': 3.1952476367591003},
"Attack_types":{'Same protocol': 0.016173764876483955},
"Real_labels": {'1': 18}
},
{
"sTime":"2023-03-24T14:22:00Z",
"eTime":"2023-03-24T14:23:00Z", 
 "Gateways": ['bergen-gw3', 'trd-gw'],
"Deviation_score":{'mean': 3.0194743025789834, 'standard_deviation': 3.5666872233297},
"Attack_types":{'Same protocol': 0.0033812480575167335},
"Real_labels": {'1': 3}
},
{
"sTime":"2023-03-24T14:22:00Z",
"eTime":"2023-03-24T14:23:00Z", 
 "Gateways": ['bergen-gw3', 'trd-gw'],
"Deviation_score":{'mean': 2.5654160898653866, 'standard_deviation': 3.0286144833831874},
"Attack_types":{'Same protocol': 0.006732302878318492},
"Real_labels": {'1': 6}
},
{
"sTime":"2023-03-24T14:24:00Z",
"eTime":"2023-03-24T14:25:00Z", 
 "Gateways": ['bergen-gw3', 'hoytek-gw2'],
"Deviation_score":{'mean': 0.256175817982834, 'standard_deviation': 0.1859383723489054},
"Attack_types":{'Different protocols': 0.002739606392794626, 'Same protocol': 0.005382233865206},
"Real_labels": {'1': 6}
},
{
"sTime":"2023-03-24T14:24:00Z",
"eTime":"2023-03-24T14:25:00Z", 
 "Gateways": ['bergen-gw3', 'hoytek-gw2'],
"Deviation_score":{'mean': 0.17829610532791218, 'standard_deviation': 0.06301462612901089},
"Attack_types":{'Different protocols': 0.001373916719509617, 'Same protocol': 0.002691116932603},
"Real_labels": {'1': 3}
},
{
"sTime":"2023-03-24T14:26:00Z",
"eTime":"2023-03-24T14:27:00Z", 
 "Gateways": ['bergen-gw3', 'teknobyen-gw1', 'ifi2-gw5', 'hoytek-gw2', 'trd-gw'],
"Deviation_score":{'mean': 10.565821871373748, 'standard_deviation': 22.384085518068602},
"Attack_types":{'Different protocols': 0.011297329505961611, 'SYN Flood': 0.011203963718463826, '': 0.00821305204971918, 'Flooding': 0.010847692864728845, 'Same protocol': 0.0013495276653171385, 'ICMP Flood': 0.0006725481663172049, 'Low-Rate': 0.0007939102414421142},
"Real_labels": {'1': 123, '0': 57376}
},
{
"sTime":"2023-03-24T14:25:00Z",
"eTime":"2023-03-24T14:26:00Z", 
 "Gateways": ['bergen-gw3', 'hoytek-gw2'],
"Deviation_score":{'mean': 3.1251656116006004, 'standard_deviation': 3.9386672700970746},
"Attack_types":{'Different protocols': 0.01624368051600125, 'Same protocol': 0.010847920318651842},
"Real_labels": {'1': 16, '0': 8}
},
{
"sTime":"2023-03-24T14:25:00Z",
"eTime":"2023-03-24T14:26:00Z", 
 "Gateways": ['bergen-gw3', 'hoytek-gw2'],
"Deviation_score":{'mean': 3.114191573994084, 'standard_deviation': 3.946436318080729},
"Attack_types":{'Different protocols': 0.01218687391011324, 'Same protocol': 0.008135940238988882},
"Real_labels": {'1': 12, '0': 6}
},
{
"sTime":"2023-03-24T14:24:00Z",
"eTime":"2023-03-24T14:25:00Z", 
 "Gateways": ['bergen-gw3', 'hoytek-gw2'],
"Deviation_score":{'mean': 1.3026867377333806, 'standard_deviation': 2.621264459035921},
"Attack_types":{'Same protocol': 0.0067446862795518215, 'Different protocols': 0.01643763835676775},
"Real_labels": {'1': 16, '0': 2}
},
{
"sTime":"2023-03-24T14:26:00Z",
"eTime":"2023-03-24T14:27:00Z", 
 "Gateways": ['bergen-gw3', 'hoytek-gw2'],
"Deviation_score":{'mean': 1.2669129683464426, 'standard_deviation': 2.632904368111458},
"Attack_types":{'Same protocol': 0.004061507744980099, 'Different protocols': 0.01912875528937075},
"Real_labels": {'0': 2, '1': 16}
},
{
"sTime":"2023-03-24T14:24:00Z",
"eTime":"2023-03-24T14:25:00Z", 
 "Gateways": ['bergen-gw3', 'hoytek-gw2'],
"Deviation_score":{'mean': 1.1729755580835974, 'standard_deviation': 2.4486126440804914},
"Attack_types":{'Same protocol': 0.0067446862795518215, 'Different protocols': 0.02052677241487952},
"Real_labels": {'1': 19, '0': 2}
},
{
"sTime":"2023-03-24T14:25:00Z",
"eTime":"2023-03-24T14:26:00Z", 
 "Gateways": ['bergen-gw3', 'hoytek-gw2'],
"Deviation_score":{'mean': 1.167793248487556, 'standard_deviation': 2.450250850927506},
"Attack_types":{'Same protocol': 0.005403097012265961, 'Different protocols': 0.021868361682165376},
"Real_labels": {'1': 19, '0': 2}
},
{
"sTime":"2023-03-24T14:24:00Z",
"eTime":"2023-03-24T14:25:00Z", 
 "Gateways": ['bergen-gw3', 'hoytek-gw2'],
"Deviation_score":{'mean': 1.073113732218341, 'standard_deviation': 2.306726919494845},
"Attack_types":{'Same protocol': 0.0067446862795518215, 'Different protocols': 0.02460796807496},
"Real_labels": {'1': 22, '0': 2}
},
{
"sTime":"2023-03-24T14:24:00Z",
"eTime":"2023-03-24T14:25:00Z", 
 "Gateways": ['bergen-gw3', 'hoytek-gw2'],
"Deviation_score":{'mean': 0.9311649640111557, 'standard_deviation': 2.0957778147948525},
"Attack_types":{'Same protocol': 0.006063460072378911, 'Different protocols': 0.013698031963973128},
"Real_labels": {'1': 14, '0': 1}
},
{
"sTime":"2023-03-24T14:25:00Z",
"eTime":"2023-03-24T14:26:00Z", 
 "Gateways": ['trd-gw', 'bergen-gw3', 'hoytek-gw2'],
"Deviation_score":{'mean': 0.8458953515345545, 'standard_deviation': 2.044095126580373},
"Attack_types":{'Different protocols': 0.01677237772299242, '': 0.01441335429435595, 'SYN Flood': 0.0023557666066896825, 'Flooding': 0.0014442896722933144, 'Same protocol': 0.0013624524143458223},
"Real_labels": {'1': 56, '0': 22870}
}]

rankingBasedOnDeviationScore = sortByAttackType(ranking)
rankingBasedOnDeviationScore = sorted(rankingBasedOnDeviationScore, key=lambda x: x["Deviation_score"]["mean"], reverse=True)
pprint(rankingBasedOnDeviationScore)
newRanking = sorted(ranking, key=lambda x: x["Deviation_score"]["mean"], reverse=True)
newRanking = sortByAttackType(newRanking)
#pprint(newRanking)'''

def precision (tp, fp):
    precision = tp/(tp+fp)
    return "%.3f"%precision

def stringPrecision(tp1, fp1, tp2, fp2, tp3, fp3):
    return precision(tp1, fp1) + " & " + precision(tp2, fp2) + " & " + precision(tp3, fp3) 

#print(stringPrecision(222,300,14707,753,23,10))
print(precision(582,460))

def reduction (before, after):
    difference = before -after
    reduced = difference/before
    return "%.3f"%reduced

def stringPrecision(tp1, fp1, tp2, fp2):
    return reduction(tp1, tp2) + " & " + reduction(fp1, fp2) 

#print(stringPrecision(222,300,14707,753,23,10))
print(stringPrecision(2890,1257,2129,221))

attacks = {"UDP Flood": {"TP": 0, "FP": 0, "TN": 117745, "FN": 171181}, "SlowLoris": {"TP": 1014, "FP": 602223, "TN": 546846, "FN": 3752}, "Ping Flood": {"TP": 671, "FP": 434296, "TN": 213721, "FN": 358}, "Slow Read": {"TP": 2231, "FP": 865013, "TN": 409501, "FN": 1079}, "Blacknurse": {"TP": 993, "FP": 680539, "TN": 226187, "FN": 483}, "SYN Flood": {"TP": 436141, "FP": 184310, "TN": 132575, "FN": 502991}, "R.U.D.Y": {"TP": 807, "FP": 546941, "TN": 237675, "FN": 401}, "Xmas": {"TP": 464808, "FP": 194996, "TN": 119985, "FN": 328448}, "UDP Flood and SlowLoris": {"TP": 590529, "FP": 569416, "TN": 304134, "FN": 748564}, "Ping Flood and R.U.D.Y": {"TP": 1321, "FP": 604609, "TN": 312477, "FN": 594}, "All types": {"TP": 697649, "FP": 578930, "TN": 220721, "FN": 481123}}
truePositives =0
falsePositives = 0
positives = 0
negatives =0
for attack in attacks:
    truePositives += attacks[attack]["TP"]
    falsePositives += attacks[attack]["FP"]
    positives += attacks[attack]["TP"] +attacks[attack]["FN"]
    negatives += attacks[attack]["FP"] +attacks[attack]["TN"]
print(falsePositives)
print(truePositives)
print(precision(truePositives, falsePositives))
print(precision(positives, negatives))
print(positives + negatives)


print(stringPrecision(1557,1366,807,55))
print(reduction(0.996,0.876))