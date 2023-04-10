from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import json

'''
    Calculates entropy and other metrics and for every minute of a week. 
    Uses a sliding window to calculate the entropy
    Stores the values in a json structure based on weekday, hour and minute.
    Input:  silkFile:   string, file with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            attackDate: string, date of the attack the calculations are made on
'''
def metricCalculation(silkFile, start, stop, frequency, interval):
    #Open file to write alerts to
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

    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []
    
    #Instantiate variables
    i = 0
    sizes = []

    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
        #Implement the sliding window
        if rec.stime > windowTime + frequency:
            lastSizes = 0
            for size in sizes:
                lastSizes += size
            thisMinuteSize = len(records) - lastSizes
            sizes.append(thisMinuteSize)
            windowTime += frequency
        #Aggregate flows into the specified time interval
        if rec.stime > startTime + interval:
            #Make dictionary for how many packets each destination flow has
            numberOfPacketsPerSIP ={}
            numberOfPacketsPerDIP ={}
            numberOfPacketsPerFlow = {}
            flows = {}
            numberOfPacketsOfSizei = {}
            #A variable to keep track of the total amount of packets in this time interval
            sumOfPackets = 0
            icmpPackets = 0
            #Loop through each flow record in the time interval
            for rec in records:
                sumOfPackets += rec.packets
                #If the current flow has the same source IP as a previous flow the number of packets is added to the record of that source IP
                #If it has not been encountered before it is added to the dictionary
                if rec.sip in numberOfPacketsPerSIP:
                    numberOfPacketsPerSIP[rec.sip] += rec.packets
                else:
                    numberOfPacketsPerSIP[rec.sip] = rec.packets
                
                if rec.dip in numberOfPacketsPerDIP:
                    numberOfPacketsPerDIP[rec.dip] += rec.packets
                else:
                    numberOfPacketsPerDIP[rec.dip] = rec.packets
                
                flow = (rec.sip, rec.dip)
                reverse_flow = (rec.dip, rec.sip)

                #Find the index of the current flow in the dictionary if it exists
                #If not add it to the dictionary 
                if flow in flows:
                    index = flows[flow]
                elif reverse_flow in flows:
                    index = flows[reverse_flow]
                    flow = reverse_flow
                else:
                    index = len(flows)
                    flows[flow] = index
                    numberOfPacketsPerFlow[index] = 0
                #Add the packets of the current flow to the corresponding index in the other dictionary
                numberOfPacketsPerFlow[index] += rec.packets

                #Check if the flow is of the ICMP protocol
                #If it is we count up the packets in the flow
                if rec.protocol == 1 or rec.protocol == 58:
                    icmpPackets += rec.packets

                #If there are no packets the size is 0
                if rec.packets == 0:
                    size = 0
                else:
                    #If there are packets the average size of a packet is calculated for this measurement, cast to an integer, and stored
                    size = int(rec.bytes/rec.packets)
                #If the size of the packet has been encountered before the number of packets with this size is increased by the number of packets
                if size in numberOfPacketsOfSizei:
                    numberOfPacketsOfSizei[size] += rec.packets
                else:
                    numberOfPacketsOfSizei[size] = rec.packets
            
            #Array to keep track of the probability distribution
            PiSIP = []
            print(numberOfPacketsPerSIP)
            #Loop through each IP flow in the time interval
            for key, value in numberOfPacketsPerSIP.items():
                print(key, value)
                #Add the probability of the current source flow having the size that it does to the distribution
                PiSIP.append(value/sumOfPackets)
            ns = len(numberOfPacketsPerSIP)
            print(ns)
            #Calculate the generalized entropy of this distribution
            entropySip = generalizedEntropy(10,PiSIP)

            PiDIP = []
            
            #Loop through each IP flow in the time interval
            for key, value in numberOfPacketsPerDIP.items():
                #Add the probability of the current source flow having the size that it does to the distribution
                PiDIP.append(value/sumOfPackets)
            nd = len(numberOfPacketsPerDIP)

            #Calculate the generalized entropy of this distribution
            entropyDip = generalizedEntropy(10,PiDIP)
            
            PiF = []

            #Loop through each flow in the time interval
            for key, value in numberOfPacketsPerFlow.items():
                #Add the probability of flow having the size that it does to the distribution
                PiF.append(value/sumOfPackets)
            nf = len(flows)
            #Calculate the generalized entropy of this distribution
            entropyFlow = generalizedEntropy(10, PiF)

            #Find the ratio of ICMP packets in this time interval
            icmpRatio = icmpPackets/sumOfPackets

            PiPS = []

            sumOfNP = sum(numberOfPacketsOfSizei.values())

            #Loop through all of the packet sizes
            for key, value in numberOfPacketsOfSizei.items():
                #Add the probability of the current packet size being the size that it does to the distribution
                PiPS.append(value/sumOfNP)
            nps = len(numberOfPacketsOfSizei)

            #Calculate the generalized entropy of this distribution
            entropyPacketSize = generalizedEntropy(10, PiPS)


            json_object_raw_sip["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(entropySip)
            json_object_raw_sip_rate["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(entropySip/ns)
            json_object_raw_dip["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(entropyDip)
            json_object_raw_dip_rate["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(entropyDip/nd)
            json_object_raw_f["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(entropyFlow)
            json_object_raw_f_rate["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(entropyFlow/nf)
            json_object_raw_nf["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(nf)
            json_object_raw_icmp_ratio["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(icmpRatio)
            json_object_raw_icmp_packets["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(icmpPackets)
            json_object_raw_packet_size["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(entropyPacketSize)
            json_object_raw_packet_size_rate["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(entropyPacketSize/nps)
            json_object_raw_packets["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(numberOfPackets(records))
            json_object_raw_bytes["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(numberOfBytes(records))

            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
    
        records.append(rec)
    

    infile.close()
    json_file_raw_sip = open("NetFlow/Entropy/Calculations/sip."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump(json_object_raw_sip,json_file_raw_sip)
    json_file_raw_sip.close()

    json_file_raw_sip_rate = open("NetFlow/Entropy/Calculations/sip_rate."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump(json_object_raw_sip_rate,json_file_raw_sip_rate)
    json_file_raw_sip_rate.close()

    json_file_raw_dip = open("NetFlow/Entropy/Calculations/dip."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump(json_object_raw_dip,json_file_raw_dip)
    json_file_raw_dip.close()

    json_file_raw_dip_rate = open("NetFlow/Entropy/Calculations/dip_rate."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump(json_object_raw_dip_rate,json_file_raw_dip_rate)
    json_file_raw_dip_rate.close()

    json_file_raw_flow = open("NetFlow/Entropy/Calculations/flow."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump(json_object_raw_f,json_file_raw_flow)
    json_file_raw_flow.close()

    json_file_raw_f_rate = open("NetFlow/Entropy/Calculations/f_rate."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump(json_object_raw_f_rate,json_file_raw_f_rate)
    json_file_raw_f_rate.close()

    json_file_raw_nf = open("NetFlow/Entropy/Calculations/nf."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump(json_object_raw_nf,json_file_raw_nf)
    json_file_raw_nf.close()

    json_file_raw_icmp_ratio = open("NetFlow/Entropy/Calculations/icmp_ratio."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump(json_object_raw_icmp_ratio,json_file_raw_icmp_ratio)
    json_file_raw_icmp_ratio.close()

    json_file_raw_icmp_packets = open("NetFlow/Entropy/Calculations/icmp_packets."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump(json_object_raw_icmp_packets,json_file_raw_icmp_packets)
    json_file_raw_icmp_packets.close()

    json_file_raw_packet_size = open("NetFlow/Entropy/Calculations/packet_size."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump(json_object_raw_packet_size,json_file_raw_packet_size)
    json_file_raw_packet_size.close()

    json_file_raw_packet_size_r = open("NetFlow/Entropy/Calculations/packet_size_r."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump(json_object_raw_packet_size_rate,json_file_raw_packet_size_r)
    json_file_raw_packet_size_r.close()

    json_file_raw_packets = open("NetFlow/Entropy/Calculations/packets."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump(json_object_raw_packets,json_file_raw_packets)
    json_file_raw_packets.close()

    json_file_raw_bytes = open("NetFlow/Entropy/Calculations/bytes."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump(json_object_raw_bytes,json_file_raw_bytes)
    json_file_raw_bytes.close()
'''    
metricCalculation("/home/linneafg/silk-data/RawDataFromFilter/one-day-2011-01-10_11-sorted.rw", "2011-01-10 00:00:00", "2011-01-11 00:00:00",timedelta(minutes = 1), timedelta(minutes = 5))'''
silkFiles = ["/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week1.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week2.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week3.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week4.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week5.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week6.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week7.rw"]
'''start="2011-01-03 00:00:00"
stop="2011-01-10 00:00:00"
metricCalculation(silkFiles[1], start, stop, timedelta(minutes = 1), timedelta(minutes = 10))
start="2011-01-10 00:00:00"
stop="2011-01-17 00:00:00"
metricCalculation(silkFiles[2], start, stop, timedelta(minutes = 1), timedelta(minutes = 10))
start="2011-01-17 00:00:00"
stop="2011-01-24 00:00:00"
metricCalculation(silkFiles[3], start, stop, timedelta(minutes = 1), timedelta(minutes = 10))
start="2011-01-24 00:00:00"
stop="2011-01-31 00:00:00"
metricCalculation(silkFiles[4], start, stop, timedelta(minutes = 1), timedelta(minutes = 10))
start="2011-01-31 00:00:00"
stop="2011-02-07 00:00:00"
metricCalculation(silkFiles[5], start, stop, timedelta(minutes = 1), timedelta(minutes = 10))
start="2011-02-07 00:00:00"
stop="2011-02-14 00:00:00"
metricCalculation(silkFiles[6], start, stop, timedelta(minutes = 1), timedelta(minutes = 10))'''