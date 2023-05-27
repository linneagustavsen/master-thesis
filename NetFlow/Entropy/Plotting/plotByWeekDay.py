import matplotlib.pyplot as plt
import json
from datetime import datetime
import matplotlib.dates as mdates

'''
    Make a plot based on arrays of values and timestamps
'''
def makePlot(jsonFile, y_field, y_fieldName, path):
    with open(jsonFile, 'r') as f:
        data = json.load(f)

    x_values = []
    y_values = [[] for _ in range(7)]  # Initialize empty lists for 7 weeks
    date = "2023-03-26"
    
    for day in data['weekday']:
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
                date_string = f'{date}-{hour}-{minute}'
                date_obj = datetime.strptime(date_string, '%Y-%m-%d-%H-%M')
                x_values.append(date_obj)
                for i, y_value in enumerate(data['weekday'][day]['hour'][hour]['minute'][minute]):
                        y_values[i].append(y_value)
                if len(data['weekday'][day]['hour'][hour]['minute'][minute]) == 6:
                    y_values[6].append(None)
                elif len(data['weekday'][day]['hour'][hour]['minute'][minute]) == 5:
                    y_values[5].append(None)
                    y_values[6].append(None)
                elif len(data['weekday'][day]['hour'][hour]['minute'][minute]) == 4:
                    y_values[4].append(None)
                    y_values[5].append(None)
                    y_values[6].append(None)
                elif len(data['weekday'][day]['hour'][hour]['minute'][minute]) == 3:
                    y_values[3].append(None)
                    y_values[4].append(None)
                    y_values[5].append(None)
                    y_values[6].append(None)
                elif len(data['weekday'][day]['hour'][hour]['minute'][minute]) == 2:
                    y_values[2].append(None)
                    y_values[3].append(None)
                    y_values[4].append(None)
                    y_values[5].append(None)
                    y_values[6].append(None)
                elif len(data['weekday'][day]['hour'][hour]['minute'][minute]) == 1:
                    y_values[1].append(None)
                    y_values[2].append(None)
                    y_values[3].append(None)
                    y_values[4].append(None)
                    y_values[5].append(None)
                    y_values[6].append(None)
                elif len(data['weekday'][day]['hour'][hour]['minute'][minute]) == 0:
                    y_values[0].append(None)
                    y_values[1].append(None)
                    y_values[2].append(None)
                    y_values[3].append(None)
                    y_values[4].append(None)
                    y_values[5].append(None)
                    y_values[6].append(None)
    
        fig, axs = plt.subplots(1, 1, figsize=(20, 5))
        for i, y_week in enumerate(y_values):
            axs.plot(x_values, y_week, label=f"Week {i+1}")
        
        axs.xaxis.set(
            major_locator=mdates.DayLocator(),
            major_formatter=mdates.DateFormatter("\n\n%A\n"),
            minor_locator=mdates.HourLocator((0, 6, 12, 18)),
            minor_formatter=mdates.DateFormatter("%H"),
        )
        axs.set_title(y_fieldName)
        axs.set_xlabel('Time')
        axs.set_ylabel(y_fieldName)
        axs.tick_params(axis='both', which='major', labelsize=12)
        axs.legend()
        fig.tight_layout()
        fig.savefig(path+y_field+day+".png", dpi=500)
        plt.close()
        x_values = []
        y_values = [[] for _ in range(7)]  # Initialize empty lists for 7 weeks

makePlot('NetFlow/Entropy/Calculations/dip_rate.300.json', 'dstEntropyRate','Entropy rate of destination IP', 'Plots/Entropy/WeekDayComparison.300.')
makePlot('NetFlow/Entropy/Calculations/dip_rate.600.json', 'dstEntropyRate','Entropy rate of destination IP', 'Plots/Entropy/WeekDayComparison.600.')

makePlot('NetFlow/Entropy/Calculations/dip.300.json', 'dstEntropy','Entropy of destination IP', 'Plots/Entropy/WeekDayComparison.300.')
makePlot('NetFlow/Entropy/Calculations/dip.600.json', 'dstEntropy','Entropy of destination IP', 'Plots/Entropy/WeekDayComparison.600.')

makePlot('NetFlow/Entropy/Calculations/f_rate.300.json', 'flowEntropyRate','Entropy rate of bi-directional flows', 'Plots/Entropy/WeekDayComparison.300.')
makePlot('NetFlow/Entropy/Calculations/f_rate.600.json', 'flowEntropyRate','Entropy rate of bi-directional flows', 'Plots/Entropy/WeekDayComparison.600.')

makePlot('NetFlow/Entropy/Calculations/flow.300.json', 'flowEntropy','Entropy of bi-directional flows', 'Plots/Entropy/WeekDayComparison.300.')
makePlot('NetFlow/Entropy/Calculations/flow.600.json', 'flowEntropy','Entropy of bi-directional flows', 'Plots/Entropy/WeekDayComparison.600.')

makePlot('NetFlow/Entropy/Calculations/sip_rate.300.json', 'srcEntropyRate','Entropy rate of source IP', 'Plots/Entropy/WeekDayComparison.300.')
makePlot('NetFlow/Entropy/Calculations/sip_rate.600.json', 'srcEntropyRate','Entropy rate of source IP', 'Plots/Entropy/WeekDayComparison.600.')

makePlot('NetFlow/Entropy/Calculations/sip.300.json', 'srcEntropy','Entropy of source IP', 'Plots/Entropy/WeekDayComparison.300.')
makePlot('NetFlow/Entropy/Calculations/sip.600.json', 'srcEntropy','Entropy of source IP', 'Plots/Entropy/WeekDayComparison.600.')

makePlot('NetFlow/Entropy/Calculations/icmp_packets.300.json', 'icmpPackets','Number of ICMP packets', 'Plots/Entropy/WeekDayComparison.300.')
makePlot('NetFlow/Entropy/Calculations/icmp_packets.600.json', 'icmpPackets','Number of ICMP packets', 'Plots/Entropy/WeekDayComparison.600.')

makePlot('NetFlow/Entropy/Calculations/icmp_ratio.300.json', 'icmpRatio','ICMP ratio', 'Plots/Entropy/WeekDayComparison.300.')
makePlot('NetFlow/Entropy/Calculations/icmp_ratio.600.json', 'icmpRatio','ICMP ratio', 'Plots/Entropy/WeekDayComparison.600.')

makePlot('NetFlow/Entropy/Calculations/nf.300.json', 'numberOfFlows','Number of flows', 'Plots/Entropy/WeekDayComparison.300.')
makePlot('NetFlow/Entropy/Calculations/nf.600.json', 'numberOfFlows','Number of flows', 'Plots/Entropy/WeekDayComparison.600.')