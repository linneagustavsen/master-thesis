import math
import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates
import pandas as pd

'''
    Make a plot based on arrays of values and timestamps
'''
def plotKmeansFields(start, stop, interval, systemId, attackDate):
    #Makes datetime objects of the input times
    fig, axs = plt.subplots(1, 1, figsize=(20, 10))

    format = '%b %d %H:%M:%S'
    strings = [
            ["Mar 08 14:29:55", "Mar 08 14:34:56"], ["Mar 08 14:49:56", "Mar 08 15:02:57"],
            ["Mar 08 15:09:56", "Mar 08 15:17:02"], ["Mar 08 15:37:00", "Mar 08 15:52:02"]]
    for string in strings:
        start = datetime.strptime(string[0], format).replace(year=2023)
        stop = datetime.strptime(string[1], format).replace(year=2023)
        axs.axvspan(start, stop, facecolor="#F9CAA4")

    
    cluster0 = pd.read_csv("Calculations0803/Kmeans/NetFlow/Entropy.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
    cluster1 = pd.read_csv("Calculations0803/Kmeans/NetFlow/Entropy.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
    sTime0 = pd.to_datetime(cluster0["sTime"])
    sTime1 = pd.to_datetime(cluster1["sTime"])

    packets0 = cluster0["number_of_packets"]
    labels0 = cluster0["real_label"]
    packets1 = cluster1["number_of_packets"]
    labels1 = cluster1["real_label"]
    
    
    #format = '%Y-%m-%dT%H:%M:%SZ'
    eTime0 = pd.to_datetime(cluster0["eTime"])
    eTime1 = pd.to_datetime(cluster1["eTime"])

    lastInterval = pd.Interval(pd.Timestamp.now().replace(tzinfo=None), pd.Timestamp.now().replace(tzinfo=None), closed="both")

    for i in range(len(labels0)):
        if labels0[i] == 1:
            if sTime0[i].replace(second=0).replace(tzinfo=None) in lastInterval and eTime0[i].replace(second=0).replace(tzinfo=None) in lastInterval:
                continue
            elif sTime0[i].replace(second=0).replace(tzinfo=None) in lastInterval:

                nowInterval = pd.Interval(lastInterval.right, eTime0[i].replace(second=0).replace(tzinfo=None)+timedelta(minutes=1), closed="both")
                lastInterval = pd.Interval(lastInterval.left, eTime0[i].replace(second=0).replace(tzinfo=None) +timedelta(minutes=1), closed="both")
            
            elif eTime0[i].replace(second=0).replace(tzinfo=None) in lastInterval:
        
                nowInterval = pd.Interval(sTime0[i].replace(second=0).replace(tzinfo=None), lastInterval.left, closed="both")
                lastInterval = pd.Interval(sTime0[i].replace(second=0).replace(tzinfo=None), lastInterval.right, closed="both")
            else:
                nowInterval = pd.Interval(sTime0[i].replace(second=0).replace(tzinfo=None), eTime0[i].replace(second=0).replace(tzinfo=None) +timedelta(minutes=1), closed="both")
                lastInterval = nowInterval

            axs.axvspan(nowInterval.left, nowInterval.right, facecolor="#2A9D8F")

    for i in range(len(labels1)):
        if labels1[i] == 1:
            if sTime1[i].replace(second=0).replace(tzinfo=None) in lastInterval and eTime1[i].replace(second=0).replace(tzinfo=None) in lastInterval:
                continue
            elif sTime1[i].replace(second=0).replace(tzinfo=None) in lastInterval:

                nowInterval = pd.Interval(lastInterval.right, eTime1[i].replace(second=0).replace(tzinfo=None)+timedelta(minutes=1), closed="both")
                lastInterval = pd.Interval(lastInterval.left, eTime1[i].replace(second=0).replace(tzinfo=None) +timedelta(minutes=1), closed="both")
            
            elif eTime1[i].replace(second=0).replace(tzinfo=None) in lastInterval:
        
                nowInterval = pd.Interval(sTime1[i].replace(second=0).replace(tzinfo=None), lastInterval.left, closed="both")
                lastInterval = pd.Interval(sTime1[i].replace(second=0).replace(tzinfo=None), lastInterval.right, closed="both")
            else:
                nowInterval = pd.Interval(sTime1[i].replace(second=0).replace(tzinfo=None), eTime1[i].replace(second=0).replace(tzinfo=None) +timedelta(minutes=1), closed="both")
                lastInterval = nowInterval

            axs.axvspan(nowInterval.left, nowInterval.right, facecolor="#61D5C7")
    timeAxis = []
    timeAxis.extend(sTime0.values)
    timeAxis.extend(sTime1.values)
    timeAxis.sort()
    newPackets0 = []
    newPackets1 = []
    counter0 = 0
    counter1 = 0
 
    for time in timeAxis:
        if time not in sTime0.values:
            newPackets0.append(None)
        elif time in sTime0.values:
            print("happened")
            newPackets0.append(packets0[counter0])
            counter0 +=1

        if time not in sTime1.values:
            newPackets1.append(None)
        elif time in sTime1.values:
            print("happened")
            newPackets1.append(packets1[counter1])
            counter1 +=1

    axs.plot(timeAxis ,newPackets0, color="#162931", label="Cluster 0")

    axs.plot(timeAxis ,newPackets1, color="#E76F51", label="Cluster 1")

    axs.xaxis.set(
        major_locator=mdates.MinuteLocator(interval=15),
        major_formatter=mdates.DateFormatter("%H:%M")
    )
    axs.set_title("Packets in each cluster")
    axs.set_xlabel('Time')
    axs.set_ylabel("Packets")
    axs.tick_params(axis='both', which='major', labelsize=12)
    axs.legend()
    
    
    fig.tight_layout()
    fig.savefig("Plots/Kmeans/Attack0803/NetFlow/Entropy/Packets."+  str(systemId)+ "."+ str(int(interval.total_seconds())) +"secInterval.png", dpi=300)
    plt.close()


systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
startKmeans = "2023-03-08 14:15:00"
stopKmeans= "2023-03-08 16:00:00"
intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
attackDate = "08.03.23"
for systemId in systems:
    for interval in intervals:
        plotKmeansFields(startKmeans, stopKmeans, interval, systemId, attackDate)
