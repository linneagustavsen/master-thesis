import json
from datetime import timedelta

from numpy import mean
interval = timedelta(minutes = 10)
files = ["sip","sip_rate","dip", "dip_rate","flow", "f_rate","nf", "icmp_ratio", "icmp_packets", "packet_size", "packet_size_r", "packets", "bytes"]
for file in files:
    minimum = 100000000000000
    values = []
    changes = []
    counter = 0
    for week in range(1,8):  
        json_file = open("NetFlow/Entropy/Calculations/"+ file +"."+ str(int(interval.total_seconds())) +".week"+ str(week)+ ".json", "r")
        json_object= json.load(json_file)
        json_file.close()

        for i in range(7):
            for j in range(24):
                for k in range(60):
                    if len(json_object["weekday"][str(i)]["hour"][str(j)]["minute"][str(k)]) > 0:
                        value = json_object["weekday"][str(i)]["hour"][str(j)]["minute"][str(k)][0]
                        values.append(value)
                        #print(len(values), counter)
                        if len(values) > 10:
                            change = abs(values[counter] - mean(values[counter-10: counter-1]))
                            changes.append(change)
                            if change < minimum:
                                minimum = change    
                        counter += 1     
    json_file = open("NetFlow/Entropy/Calculations/MinMaxValues/MinMax."+ file +"."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": minimum, "maximum": 3*mean(changes)},json_file)
    json_file.close()