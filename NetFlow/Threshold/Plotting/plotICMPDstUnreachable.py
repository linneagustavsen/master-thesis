import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates
import pandas as pd

'''
    Make a plot based on arrays of values and timestamps
'''
def makePlotICMPDstUnreachable(systemId, interval, attackDate):
    #data = pd.read_csv("Calculations0803/Threshold/NetFlow/ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
    data = pd.read_csv("/Users/linneafgustavsen/Desktop/Masteroppgave/FromAttack23/Calculations/Threshold/NetFlow//ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
    
    #attackFlows = pd.read_csv("Calculations0803/Threshold/NetFlow/AttackFlows.ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
    attackFlows = pd.read_csv("/Users/linneafgustavsen/Desktop/Masteroppgave/FromAttack23/Calculations/Threshold/NetFlow/AttackFlows.ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
    startTime = pd.to_datetime(attackFlows["sTime"])
    endTime = pd.to_datetime(attackFlows["eTime"])

    y_values = data["ICMPDstUnreachable"]

    if len(y_values) == 0:
        return
    if len(startTime) == 0:
        return
    timeAxis = pd.to_datetime(data["sTime"])
    print(timeAxis[0])
    format = '%b %d %H:%M:%S'
    timeAxis[0] = datetime.strptime("Mar 17 11:00:00", format).replace(year=2023)
    print(timeAxis[0])          
    fig, axs = plt.subplots(1, 1, figsize=(20, 5))
   
    axs.plot(timeAxis ,y_values, color="#162931")
    format = '%b %d %H:%M:%S'
    '''strings = [
            ["Mar 08 14:29:55", "Mar 08 14:34:56"], ["Mar 08 14:49:56", "Mar 08 15:02:57"],
            ["Mar 08 15:09:56", "Mar 08 15:17:02"], ["Mar 08 15:37:00", "Mar 08 15:52:02"]]'''
    strings = [["Mar 17 11:00:01", "Mar 17 11:07:02"], ["Mar 17 11:37:02", "Mar 17 11:50:04"],
           ["Mar 17 11:57:02", "Mar 17 12:04:12"], ["Mar 17 12:44:10", "Mar 17 13:00:17"]]
    attacks = ["SYN Flood", "SlowLoris", "Ping Flood", "R.U.D.Y"]
    colors = ["#CB997E","#DDBEA9", "#FFE8D6", "#B7B7A4"]
    '''strings = [["Mar 24 14:00:01", "Mar 24 14:03:57"], ["Mar 24 14:13:29", "Mar 24 14:29:08"],
           ["Mar 24 14:46:30", "Mar 24 14:55:00"], ["Mar 24 14:59:50", "Mar 24 15:15:06"], 
           ["Mar 24 15:26:51", "Mar 24 15:39:22"], ["Mar 24 15:40:21", "Mar 24 15:47:50"], 
           ["Mar 24 16:07:29", "Mar 24 16:19:00"], ["Mar 24 16:22:29", "Mar 24 16:29:13"],
           ["Mar 24 16:29:53", "Mar 24 16:49:50"], ["Mar 24 16:53:22", "Mar 24 17:09:39"],
           ["Mar 24 17:25:15", "Mar 24 17:47:00"]]
    attacks = ["UDP Flood", "SlowLoris", "Ping Flood", "Slow Read", "Blacknurse", "SYN Flood", "R.U.D.Y",
                "Xmas", "UDP Flood and SlowLoris", "Ping Flood and R.U.D.Y", "All types"]
    colors = ["#EDDCD2","#FFF1E6", "#FDE2E4", "#FAD2E1", "#C5DEDD", "#DBE7E4", "#F0EFEB", "#D6E2E9", "#BCD4E6","#A2C7E1", "#99C1DE"]'''
    counterStrings = 0
    for string in strings:
        start = datetime.strptime(string[0], format).replace(year=2023)
        stop = datetime.strptime(string[1], format).replace(year=2023)
        axs.axvspan(start, stop, facecolor=colors[counterStrings], label=attacks[counterStrings])
        counterStrings += 1
    
    #format = '%Y-%m-%dT%H:%M:%SZ'
    
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

        axs.axvspan(nowInterval.left, nowInterval.right, facecolor="#7F6A93")
    
    axs.axvspan(nowInterval.left,nowInterval.right, facecolor="#7F6A93", label="Attack flows")
    axs.xaxis.set(
        major_locator=mdates.MinuteLocator(interval=15),
        major_formatter=mdates.DateFormatter("%H:%M"),
        
    )
    axs.set_title("ICMP destination unreachable packets", fontsize=20)
    axs.set_xlabel('Time', fontsize=15)
    axs.set_ylabel("ICMP destination unreachable packets", fontsize=15)
    axs.tick_params(axis='both', which='major', labelsize=12)
    fig.legend()
    #fig.tight_layout()
    fig.savefig("Plots/Threshold/Attack1703/NetFlow/ICMPDstUnreachable/"+  str(systemId)+ "." + str("ICMPDstUnreachable")+ "."+ str(int(interval.total_seconds())) +"secInterval.png", dpi=300)
    plt.close()


systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]

intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
attackDate = "17.03.23"
for interval in intervals:
    print(interval)
    for systemId in systems:
        print(systemId)
        makePlotICMPDstUnreachable(systemId, interval, attackDate)