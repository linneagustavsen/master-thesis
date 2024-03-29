import math
import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates
import pandas as pd

'''
    Make a plot based on arrays of values and timestamps
'''
def plotKmeansFields(start, stop, clusterFrequency, systemId, attackDate):
    if attackDate == "08.03.23":
        fileString = "0803"
        strings = [
            ["Mar 08 14:29:55", "Mar 08 14:34:56"], ["Mar 08 14:49:56", "Mar 08 15:02:57"],
            ["Mar 08 15:09:56", "Mar 08 15:17:02"], ["Mar 08 15:37:00", "Mar 08 15:52:02"]]
        attacks = ["SYN Flood", "SlowLoris", "Ping Flood", "R.U.D.Y"]
        colors = ["#CB997E","#DDBEA9", "#99958C", "#B7B7A4", "#7F6A93"]
        startTime = datetime.strptime("2023-03-08 14:15:00", '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime("2023-03-08 16:00:00", '%Y-%m-%d %H:%M:%S')
    elif attackDate == "17.03.23":
        fileString = "1703"
        strings = [["Mar 17 11:00:01", "Mar 17 11:07:02"], ["Mar 17 11:37:02", "Mar 17 11:50:04"],
           ["Mar 17 11:57:02", "Mar 17 12:04:12"], ["Mar 17 12:44:10", "Mar 17 13:00:17"]]
        attacks = ["SYN Flood", "SlowLoris", "Ping Flood", "R.U.D.Y"]
        colors = ["#CB997E","#DDBEA9", "#99958C", "#B7B7A4", "#7F6A93"]
        startTime = datetime.strptime("2023-03-17 11:00:00", '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime("2023-03-17 13:00:00", '%Y-%m-%d %H:%M:%S')
    elif attackDate == "24.03.23":
        fileString = "2403"
        strings = [["Mar 24 14:00:01", "Mar 24 14:03:57"], ["Mar 24 14:13:29", "Mar 24 14:29:08"],
           ["Mar 24 14:46:30", "Mar 24 14:55:00"], ["Mar 24 14:59:50", "Mar 24 15:15:06"], 
           ["Mar 24 15:26:51", "Mar 24 15:39:22"], ["Mar 24 15:40:21", "Mar 24 15:47:50"], 
           ["Mar 24 16:07:29", "Mar 24 16:19:00"], ["Mar 24 16:22:29", "Mar 24 16:29:13"],
           ["Mar 24 16:29:53", "Mar 24 16:49:50"], ["Mar 24 16:53:22", "Mar 24 17:09:39"],
           ["Mar 24 17:25:15", "Mar 24 17:47:00"]]
        attacks = ["UDP Flood", "SlowLoris", "Ping Flood", "Slow Read", "Blacknurse", "SYN Flood", "R.U.D.Y",
                "Xmas", "UDP Flood\nand SlowLoris", "Ping Flood\nand R.U.D.Y", "All types"]
        colors = ['#CABBB1','#BDAA9D','#AD9585','#997B66','#D08C60',"#DAA684",'#FFC876','#F1DCA7','#D9AE94','#9B9B7A','#797D62', "#7F6A93"]
        startTime = datetime.strptime("2023-03-24 14:00:00", '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime("2023-03-24 18:00:00", '%Y-%m-%d %H:%M:%S')
    #Makes datetime objects of the input times
    
    
    intervalTime = (stopTime - startTime).total_seconds()/clusterFrequency.total_seconds()
    packetsClusterAttack = []
    sTimeClusterAttack = []
    attackFlows = []
    normalFlows = []
    i= 0
    isAttack = False
    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + clusterFrequency
        clusterLabels = pd.read_csv("Calculations"+ fileString+ "/Kmeans/NetFlow/ClusterLabelling.attack."+str(attackDate)+ ".stopTime." + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
        if len(clusterLabels["AttackCluster"]) ==0:
            continue
        attackCluster = pd.read_csv("Calculations"+ fileString+ "/Kmeans/NetFlow/Fields.attack."+str(attackDate)+ ".stopTime." + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
        
        sTimeAttack = pd.to_datetime(attackCluster["sTime"])

        packetsAttack = attackCluster["packets"]
        labelsAttack = attackCluster["real_label"]
        
        i= 0
        for label in labelsAttack:
            if label == 1:
                attackFlows.append(packetsAttack[i])
                normalFlows.append(None)
                isAttack = True
            elif label == 0:
                attackFlows.append(None)
                normalFlows.append(packetsAttack[i])
            else:
                print("is not triggered")
            sTimeClusterAttack.append(sTimeAttack[i].replace(tzinfo=None))
            i+=1
            

        startTime += clusterFrequency
    if not isAttack:
        print("There was no attack")
        return
    
    fig, axs = plt.subplots(1, 1, figsize=(20, 10))

    format = '%b %d %H:%M:%S'
    
    counterStrings = 0
    for string in strings:
        start = datetime.strptime(string[0], format).replace(year=2023)
        stop = datetime.strptime(string[1], format).replace(year=2023)
        axs.axvspan(start, stop, facecolor=colors[counterStrings], label=attacks[counterStrings])
        #axs[1].axvspan(start, stop, facecolor=colors[counterStrings], label=attacks[counterStrings])
        counterStrings += 1
    axs.plot(sTimeClusterAttack ,normalFlows, color="#162931", label="False positives")
    axs.scatter(sTimeClusterAttack ,attackFlows, color="darkRed", label="True positives")

    axs.xaxis.set(
        major_locator=mdates.MinuteLocator(byminute=[0, 15, 30, 45]),
        major_formatter=mdates.DateFormatter("%H:%M")
    )
    axs.set_title("Packets in cluster labeled attack")
    axs.title.set_size(20)
    axs.set_xlabel('Time',fontsize=20)
    axs.set_ylabel("Packets", fontsize=20)
    #axs.ylabel.set_size(15)
    #axs.xlabel.set_size(15)
    #axs.set_ylim([0,maxValue])
    axs.tick_params(axis='both', which='major', labelsize=15)
    if attackDate == "24.03.23":
        fig.legend(fontsize=17)
    else:
        fig.legend(fontsize=20)
    #axs.text(0.7, 0.9, 'Labeled attack cluster: ' + str(deviation), horizontalalignment='center', verticalalignment='center', transform=ax.transAxes, bbox=dict(facecolor='blue', alpha=0.2))

    '''axs[1].xaxis.set(
        major_locator=mdates.MinuteLocator(interval=15),
        major_formatter=mdates.DateFormatter("%H:%M")
    )
    axs[1].set_xlabel('Time', fontsize=20)
    axs[1].set_ylabel("Packets", fontsize=20)
    #axs[1].ylabel.set_size(15)
    #axs[1].xlabel.set_size(15)
    axs[1].set_ylim([0,maxValue])
    axs[1].tick_params(axis='both', which='major', labelsize=15)
    axs[1].legend(fontsize=20)'''
    #fig.tight_layout()
    fig.savefig("Plots/Kmeans/Attack"+ fileString+ "/NetFlow/Fields/Packets.Both."+  str(systemId)+ ".jpg", format="jpg")
    plt.close(fig)


systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]

systems = ["tromso-gw5"]
startKmeans = "2023-03-08 14:15:00"
stopKmeans= "2023-03-08 16:00:00"
clusterFrequency = timedelta(minutes = 15)
attackDates = ["24.03.23"]
'''for attackDate in attackDates:
    for systemId in systems:
        plotKmeansFields(startKmeans, stopKmeans, clusterFrequency, systemId, attackDate)'''
plotKmeansFields(startKmeans, stopKmeans, clusterFrequency, "tromso-gw5", "24.03.23")