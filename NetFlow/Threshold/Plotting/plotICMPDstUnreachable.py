import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates
import pandas as pd

'''
    Make a plot based on arrays of values and timestamps
'''
def makePlotICMPDstUnreachable(systemId, interval, attackDate):
    data = pd.read_csv("Calculations0803/Threshold/NetFlow/ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    timeAxis = pd.to_datetime(data["eTime"])

    y_values = data["ICMPDstUnreachable"]
                      
    fig, axs = plt.subplots(1, 1, figsize=(20, 5))
   
    axs.plot(timeAxis ,y_values, color="#162931")
    format = '%b %d %H:%M:%S'
    strings = [
            ["Mar 08 14:29:55", "Mar 08 14:34:56"], ["Mar 08 14:49:56", "Mar 08 15:02:57"],
            ["Mar 08 15:09:56", "Mar 08 15:17:02"], ["Mar 08 15:37:00", "Mar 08 15:52:02"]]
    for string in strings:
        start = datetime.strptime(string[0], format).replace(year=2023)
        stop = datetime.strptime(string[1], format).replace(year=2023)
        axs.axvspan(start, stop, facecolor="#F9CAA4")
    
    #format = '%Y-%m-%dT%H:%M:%SZ'
    attackFlows = pd.read_csv("Calculations0803/Threshold/NetFlow/AttackFlows.ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
    startTime = pd.to_datetime(attackFlows["sTime"])
    endTime = pd.to_datetime(attackFlows["eTime"])
    lastInterval = pd.Interval(pd.Timestamp.now().replace(tzinfo=None), pd.Timestamp.now().replace(tzinfo=None), closed="both")

    for i in range(len(startTime)):
        if startTime[i].replace(second=0).replace(tzinfo=None) in lastInterval and endTime[i].replace(second=0).replace(tzinfo=None) in lastInterval:
            continue
        elif startTime[i].replace(second=0).replace(tzinfo=None) in lastInterval:

            nowInterval = pd.Interval(lastInterval.right, endTime[i].replace(second=0).replace(tzinfo=None)+timedelta(minutes=1), closed="both")
            lastInterval = pd.Interval(lastInterval.left, endTime[i].replace(second=0).replace(tzinfo=None) +timedelta(minutes=1), closed="both")
        
        elif endTime[i].replace(second=0).replace(tzinfo=None) in lastInterval:
     
            nowInterval = pd.Interval(startTime[i].replace(second=0).replace(tzinfo=None), lastInterval.left, closed="both")
            lastInterval = pd.Interval(startTime[i].replace(second=0).replace(tzinfo=None), lastInterval.right, closed="both")
        else:
            nowInterval = pd.Interval(startTime[i].replace(second=0).replace(tzinfo=None), endTime[i].replace(second=0).replace(tzinfo=None) +timedelta(minutes=1), closed="both")
            lastInterval = nowInterval

        axs.axvspan(nowInterval.left, nowInterval.right, facecolor="#2A9D8F")
    axs.xaxis.set(
        major_locator=mdates.HourLocator(),
        major_formatter=mdates.DateFormatter("%H"),
    )
    axs.set_title("ICMP destination unreachable packets")
    axs.set_xlabel('Time')
    axs.set_ylabel("ICMP destination unreachable packets")
    axs.tick_params(axis='both', which='major', labelsize=12)
    fig.tight_layout()
    fig.savefig("Plots/Threshold/Attack0803/NetFlow/ICMPDstUnreachable/"+  str(systemId)+ "." + str("ICMPDstUnreachable")+ "."+ str(int(interval.total_seconds())) +"secInterval.png", dpi=300)
    plt.close()


systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]

intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
attackDate = "08.03.23"
for systemId in systems:
    for interval in intervals:
        makePlotICMPDstUnreachable(systemId, interval, attackDate)
