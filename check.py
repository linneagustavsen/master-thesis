import json
from datetime import timedelta
interval = timedelta(minutes = 10)
json_file_raw_sip = open("NetFlow/Entropy/Calculations/sip."+ str(int(interval.total_seconds())) +".json", "r")
json_object_raw_sip = json.load(json_file_raw_sip)
json_file_raw_sip.close()

json_file_raw_sip_rate = open("NetFlow/Entropy/Calculations/sip_rate."+ str(int(interval.total_seconds())) +".json", "r")
json_object_raw_sip_rate = json.load(json_file_raw_sip_rate)
json_file_raw_sip_rate.close()

json_file_raw_dip = open("NetFlow/Entropy/Calculations/dip."+ str(int(interval.total_seconds())) +".json", "r")
json_object_raw_dip = json.load(json_file_raw_dip)
json_file_raw_dip.close()

json_file_raw_dip_rate = open("NetFlow/Entropy/Calculations/dip_rate."+ str(int(interval.total_seconds())) +".json", "r")
json_object_raw_dip_rate = json.load(json_file_raw_dip_rate)
json_file_raw_dip_rate.close()

json_file_raw_flow = open("NetFlow/Entropy/Calculations/flow."+ str(int(interval.total_seconds())) +".json", "r")
json_object_raw_f = json.load(json_file_raw_flow)
json_file_raw_flow.close()

json_file_raw_f_rate = open("NetFlow/Entropy/Calculations/f_rate."+ str(int(interval.total_seconds())) +".json", "r")
json_object_raw_f_rate = json.load(json_file_raw_f_rate)
json_file_raw_f_rate.close()

json_file_raw_nf = open("NetFlow/Entropy/Calculations/nf."+ str(int(interval.total_seconds())) +".json", "r")
json_object_raw_nf = json.load(json_file_raw_nf)
json_file_raw_nf.close()

json_file_raw_icmp_ratio = open("NetFlow/Entropy/Calculations/icmp_ratio."+ str(int(interval.total_seconds())) +".json", "r")
json_object_raw_icmp_ratio = json.load(json_file_raw_icmp_ratio)
json_file_raw_icmp_ratio.close()

json_file_raw_icmp_packets = open("NetFlow/Entropy/Calculations/icmp_packets."+ str(int(interval.total_seconds())) +".json", "r")
json_object_raw_icmp_packets = json.load(json_file_raw_icmp_packets)
json_file_raw_icmp_packets.close()

json_file_raw_packet_size = open("NetFlow/Entropy/Calculations/packet_size."+ str(int(interval.total_seconds())) +".json", "r")
json_object_raw_packet_size = json.load(json_file_raw_packet_size)
json_file_raw_packet_size.close()

json_file_raw_packet_size_r = open("NetFlow/Entropy/Calculations/packet_size_r."+ str(int(interval.total_seconds())) +".json", "r")
json_object_raw_packet_size_rate = json.load(json_file_raw_packet_size_r)
json_file_raw_packet_size_r.close()

json_file_raw_packets = open("NetFlow/Entropy/Calculations/packets."+ str(int(interval.total_seconds())) +".json", "r")
json_object_raw_packets = json.load(json_file_raw_packets)
json_file_raw_packets.close()

json_file_raw_bytes = open("NetFlow/Entropy/Calculations/bytes."+ str(int(interval.total_seconds())) +".json", "r")
json_object_raw_bytes = json.load(json_file_raw_bytes)
json_file_raw_bytes.close()
counter = 0
for i in range(7):
    for j in range(24):
        for k in range(60):
            length = len(json_object_raw_bytes["weekday"][str(i)]["hour"][str(j)]["minute"][str(k)])
            if length >= 10:
                print("weekday " + str(i) + " hour " + str(j) +  " minute " + str(k))
                counter +=1

print(counter)