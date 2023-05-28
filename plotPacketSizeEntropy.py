import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates
import pandas as pd

'''
    Make a plot based on arrays of values and timestamps
'''
def makePlot(y_fieldN, y_fieldT, y_fieldName, systemId, interval, attackDate):
    data = pd.read_csv("Calculations0803/Entropy/NetFlow/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
    telemetryData = pd.read_csv("Calculations/Entropy/Telemetry/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    timeAxisN = pd.to_datetime(data["eTime"])
    timeAxisT = pd.to_datetime(telemetryData["eTime"])

    y_valuesN = data[y_fieldN]
    y_valuesT = telemetryData[y_fieldT]
                      
    fig, axs = plt.subplots(2, 1, figsize=(20, 10))
   
    axs[0].plot(timeAxisN ,y_valuesN, color="#162931")
    axs[1].plot(timeAxisT ,y_valuesT, color="#162931")
    format = '%b %d %H:%M:%S'
    strings = [
            ["Mar 08 14:29:55", "Mar 08 14:34:56"], ["Mar 08 14:49:56", "Mar 08 15:02:57"],
            ["Mar 08 15:09:56", "Mar 08 15:17:02"], ["Mar 08 15:37:00", "Mar 08 15:52:02"]]
    for string in strings:
        start = datetime.strptime(string[0], format).replace(year=2023)
        stop = datetime.strptime(string[1], format).replace(year=2023)
        axs[0].axvspan(start, stop, facecolor="#F9CAA4")
        axs[1].axvspan(start, stop, facecolor="#F9CAA4")
    
    #format = '%Y-%m-%dT%H:%M:%SZ'
    attackFlows = pd.read_csv("Calculations0803/Entropy/NetFlow/AttackFlows."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
    startTime = pd.to_datetime(attackFlows["sTime"])
    endTime = pd.to_datetime(attackFlows["eTime"])
    lastInterval = pd.Interval(pd.Timestamp.now().replace(tzinfo=None), pd.Timestamp.now().replace(tzinfo=None), closed="both")

    for i in range(len(startTime)):
        if startTime[i].replace(second=0).replace(tzinfo=None) in lastInterval and endTime[i].replace(second=0).replace(tzinfo=None) in lastInterval:
            continue
        elif startTime[i].replace(second=0).replace(tzinfo=None) in lastInterval:

            nowInterval = pd.Interval(lastInterval.right, endTime[i].replace(second=0).replace(tzinfo=None), closed="both")
            lastInterval = pd.Interval(lastInterval.left, endTime[i].replace(second=0).replace(tzinfo=None), closed="both")
        
        elif endTime[i].replace(second=0).replace(tzinfo=None) in lastInterval:
     
            nowInterval = pd.Interval(startTime[i].replace(second=0).replace(tzinfo=None), lastInterval.left, closed="both")
            lastInterval = pd.Interval(startTime[i].replace(second=0).replace(tzinfo=None), lastInterval.right, closed="both")
        else:
            nowInterval = pd.Interval(startTime[i].replace(second=0).replace(tzinfo=None), endTime[i].replace(second=0).replace(tzinfo=None), closed="both")
            lastInterval = nowInterval

        axs[0].axvspan(nowInterval.left, nowInterval.right, facecolor="#efd595")
    axs[0].xaxis.set(
        major_locator=mdates.HourLocator(),
        major_formatter=mdates.DateFormatter("%H"),
    )
    axs[0].set_title(y_fieldName + " on NetFlow data")
    axs[0].set_xlabel('Time')
    axs[0].set_ylabel(y_fieldName)
    axs[0].tick_params(axis='both', which='major', labelsize=12)

    axs[1].xaxis.set(
        major_locator=mdates.HourLocator(),
        major_formatter=mdates.DateFormatter("%H"),
    )
    axs[1].set_title(y_fieldName+ " on telemetry data")
    axs[1].set_xlabel('Time')
    axs[1].set_ylabel(y_fieldName)
    axs[1].tick_params(axis='both', which='major', labelsize=12)
    fig.tight_layout()
    fig.savefig("Plots/Entropy/Attack0803/NetFlow/PacketSize/"+  str(systemId)+ "." + str(y_fieldN)+ "."+ str(int(interval.total_seconds())) +"secInterval.png", dpi=500)
    plt.close(fig)


systems = ["hovedbygget-gw", "trd-gw", "teknobyen-gw2", "teknobyen-gw1", "ifi2-gw5", 
            "oslo-gw1", "tromso-gw5", "stangnes-gw", "rodbergvn-gw2", "narvik-kv-gw", "narvik-gw3", "tromso-fh-gw",
            "ma2-gw", "narvik-gw4"]
y_fieldN = ["packetSizeEntropy", "packetSizeEntropyRate"]
y_fieldT = ["entropy_packet_size","entropy_rate_packet_size"]
y_field_names = ["Entropy of packet size", "Entropy rate of packet size"]

intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
attackDate = "08.03.23"
for systemId in systems:
    for i in range(len(y_field_names)):
        for interval in intervals:
            makePlot(y_fieldN[i], y_fieldT[i], y_field_names[i], systemId, interval, attackDate)
