import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates
import pandas as pd

'''
    Make a plot based on arrays of values and timestamps
'''
def plotSYN(systemId, attackDate):
    data = pd.read_csv("Calculations0803/Threshold/NetFlow/SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    startTime = pd.to_datetime(data["sTime"])

    y_values = data["synPacketsPerFlow"]
    labels = data["real_label"]
    if len(y_values) == 0:
        return
    fig, axs = plt.subplots(1, 1, figsize=(20, 5))
   
    axs.plot(startTime ,y_values, color="#162931")
    format = '%b %d %H:%M:%S'
    strings = [
            ["Mar 08 14:29:55", "Mar 08 14:34:56"], ["Mar 08 14:49:56", "Mar 08 15:02:57"],
            ["Mar 08 15:09:56", "Mar 08 15:17:02"], ["Mar 08 15:37:00", "Mar 08 15:52:02"]]
    for string in strings:
        start = datetime.strptime(string[0], format).replace(year=2023)
        stop = datetime.strptime(string[1], format).replace(year=2023)
        axs.axvspan(start, stop, facecolor="#F9CAA4")
    
    #format = '%Y-%m-%dT%H:%M:%SZ'
    endTime = pd.to_datetime(data["eTime"])
    
    lastInterval = pd.Interval(pd.Timestamp.now().replace(tzinfo=None), pd.Timestamp.now().replace(tzinfo=None), closed="both")

    for i in range(len(labels)):
        if labels[i] == 1:
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
    axs.set_title("SYN packets per flow")
    axs.set_xlabel('Time')
    axs.set_ylabel("SYN packets per flow")
    axs.tick_params(axis='both', which='major', labelsize=12)
    fig.tight_layout()
    fig.savefig("Plots/Threshold/Attack0803/NetFlow/SYN/"+  str(systemId)+ ".SYN.png", dpi=300)
    plt.close()


systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]

attackDate = "08.03.23"
for systemId in systems:
    plotSYN(systemId, attackDate)
