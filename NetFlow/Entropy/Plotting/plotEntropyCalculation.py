import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates
import pandas as pd

'''
    Make a plot based on arrays of values and timestamps
'''
def makePlot(y_field, y_fieldName, systemId, interval, attackDate):
    data = pd.read_csv("Calculations0803/Entropy/NetFlow/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    timeAxis = pd.to_datetime(data["eTime"])

    y_values = data[y_field]
                    
    print(y_values)    
    fig, axs = plt.subplots(1, 1, figsize=(20, 5))

    print(timeAxis)
   
    axs.plot(timeAxis ,y_values, color="#162931")
    format = '%b %d %H:%M:%S'
    strings = [
            ["Mar 08 14:29:55", "Mar 08 14:34:56"], ["Mar 08 14:49:56", "Mar 08 15:02:57"],
            ["Mar 08 15:09:56", "Mar 08 15:17:02"], ["Mar 08 15:37:00", "Mar 08 15:52:02"]]
 
    for string in strings:
        print(range(int(y_values.min()),int(y_values.max())+1))
        start = datetime.strptime(string[0], format).replace(year=2023)
        stop = datetime.strptime(string[1], format).replace(year=2023)
        axs.axvspan(start, stop, facecolor="#efd595")
    axs.xaxis.set(
        major_locator=mdates.HourLocator(),
        major_formatter=mdates.DateFormatter("%H"),
    )
    axs.set_title(y_fieldName)
    axs.set_xlabel('Time')
    axs.set_ylabel(y_fieldName)
    axs.tick_params(axis='both', which='major', labelsize=12)
    fig.tight_layout()
    fig.savefig("Plots/Entropy/Attack0803/NetFlow/"+  str(systemId)+ "." + str(y_field)+ "."+ str(int(interval.total_seconds())) +"secInterval.png", dpi=300)
    plt.close()


systems = ["bergen-gw3", "hoytek-gw2", "hovedbygget-gw", "trd-gw", "teknobyen-gw2", "teknobyen-gw1", "ifi2-gw5", 
            "oslo-gw1", "tromso-gw5", "stangnes-gw", "rodbergvn-gw2", "narvik-kv-gw", "narvik-gw3", "tromso-fh-gw",
            "ma2-gw", "narvik-gw4"]
y_fields = ["srcEntropy", "srcEntropyRate", "dstEntropy", "dstEntropyRate", "flowEntropy", "flowEntropyRate", "numberOfFlows", "icmpRatio", 
            "icmpPackets", "packetSizeEntropy", "packetSizeEntropyRate", "numberOfPackets", "numberOfBytes"]
y_field_names = ["Entropy of source IP addresses", "Entropy rate of source IP addresses", "Entropy of destination IP addresses", 
                 "Entropy rate of destination IP addresses", "Entropy of bi-directional flows", "Entropy rate of bi-directional flows", 
                 "Number of bi-directional flows", "ICMP ratio", "Number of ICMP packets", "Entropy of packet size", "Entropy rate of packet size",
                 "Number of packets", "Number of bytes"]

intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
attackDate = "08.03.23"
for systemId in systems:
    for interval in intervals:
        counter1 = 0
        for y_field in y_fields:
            makePlot(y_field, y_field_names[counter1], systemId, interval, attackDate)
            counter1 += 1
            break
        break
    break