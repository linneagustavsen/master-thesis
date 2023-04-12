import json
from datetime import timedelta
interval = timedelta(minutes = 10)
for week in range(1,8):
    files = ["sip","sip_rate","dip", "dip_rate","flow", "f_rate","nf", "icmp_ratio", "icmp_packets", "packet_size", "packet_size_r", "packets", "bytes"]
    print(week)
    for file in files:    
        json_file = open("NetFlow/Entropy/Calculations/"+ file +"."+ str(int(interval.total_seconds())) +".week"+ str(week)+ ".json", "r")
        json_object= json.load(json_file)
        json_file.close()

        
        counter = 0
        for i in range(7):
            for j in range(24):
                for k in range(60):
                    length = len(json_object["weekday"][str(i)]["hour"][str(j)]["minute"][str(k)])
                    if length >1:
                        #print("weekday " + str(i) + " hour " + str(j) +  " minute " + str(k))
                        print(length)
                        counter +=1
                    
                
        print(file,counter)