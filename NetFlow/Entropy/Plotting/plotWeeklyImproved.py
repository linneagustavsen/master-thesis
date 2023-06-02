import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates

'''
    Make a plot based on arrays of values and timestamps
'''
def makePlot(jsonFile, y_field, y_fieldName, path, interval):
    x_values = []
    y_values = [[] for _ in range(7)]  # Initialize empty lists for 7 weeks
    date = "2023-03-26"
    
    for week in range(1,8):
        with open("NetFlow/Entropy/Calculations/"+ jsonFile +"."+ str(int(interval.total_seconds())) +".week"+ str(week)+ ".json", 'r') as f:
            data = json.load(f)
        for day in data['weekday']:
            if week == 1:
                if day == '0':
                    date = "2023-03-26"
                if day == '1':
                    date = "2023-03-20"
                if day == '2':
                    date = "2023-03-21"
                if day == '3':
                    date = "2023-03-22"
                if day == '4':
                    date = "2023-03-23"
                if day == '5':
                    date = "2023-03-24"
                if day == '6':
                    date = "2023-03-25"
            for hour in data['weekday'][day]['hour']:
                for minute in data['weekday'][day]['hour'][hour]['minute']:
                    if week == 1:
                        date_string = f'{date}-{hour}-{minute}'
                        date_obj = datetime.strptime(date_string, '%Y-%m-%d-%H-%M')
                        x_values.append(date_obj)
                    if len(data['weekday'][day]['hour'][hour]['minute'][minute]) == 0:
                        y_values[week-1].append(None)
                    else:
                        y_values[week-1].append(data['weekday'][day]['hour'][hour]['minute'][minute][0])
 
                    
    #print(x_values)    
    fig, axs = plt.subplots(1, 1, figsize=(20, 7))

    #print(x_values)
    for i, y_week in enumerate(y_values):
        axs.plot(x_values, y_week, label=f"Week {i+1}")
    axs.xaxis.set(
        major_locator=mdates.DayLocator(),
        major_formatter=mdates.DateFormatter("\n\n%A\n"),
        minor_locator=mdates.HourLocator((0, 12)),
        minor_formatter=mdates.DateFormatter("%H"),
    )
    axs.set_title(y_fieldName, fontsize=20)
    axs.set_xlabel('Time', fontsize=20)
    axs.set_ylabel(y_fieldName, fontsize=20)
    axs.tick_params(axis='both', which='major', labelsize=15)
    axs.legend(fontsize=15)
    fig.tight_layout()
    fig.savefig(path+y_field+".png", dpi=500)
    plt.close(fig)


files = ["sip","sip_rate","dip", "dip_rate","flow", "f_rate","nf", "icmp_ratio", "icmp_packets", "packet_size", "packet_size_r", "packets", "bytes"]
y_fields = ["srcEntropy", "srcEntropyRate", "dstEntropy", "dstEntropyRate", "flowEntropy", "flowEntropyRate", "numberOfFlows", "icmpRatio", 
            "icmpPackets", "packetSizeEntropy", "packetSizeEntropyRate", "numberOfPackets", "numberOfBytes"]
y_field_names = ["Entropy of source IP flows", "Entropy rate of source IP flows", "Entropy of destination IP flows", 
                 "Entropy rate of destination IP flows", "Entropy of bi-directional flows", "Entropy rate of bi-directional flows", 
                 "Number of bi-directional flows", "ICMP ratio", "Number of ICMP packets", "Entropy of packet size", "Entropy rate of packet size",
                 "Number of packets", "Number of bytes"]
files = ["nf", "icmp_ratio"]
y_fields = ["numberOfFlows", "icmpRatio"]
y_field_names = ["Number of bi-directional flows", "ICMP ratio"]
counter1 = 0
for file in files:
    makePlot(file, y_fields[counter1], y_field_names[counter1], 'Plots/Entropy/ImprovedWeeklyComparison.600.', timedelta(minutes = 10))
    counter1 += 1