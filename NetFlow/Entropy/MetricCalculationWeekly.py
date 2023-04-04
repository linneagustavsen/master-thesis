from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import json

'''
    Calculates entropy and other metrics and for every minute of a week. 
    Uses a sliding window to calculate the entropy
    Stores the values in a json structure based on weekday, hour and minute.
    Input:  silkFile:   string, File with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            attackDate: string, date of the attack the calculations are made on
'''
def metricCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate):
    #Open file to write alerts to
    json_file = open("NetFlow/Entropy/Schemas/RawValuesSchema.json", "r")
    json_object_raw_sip = json.load(json_file)
    json_file = open("NetFlow/Entropy/Schemas/RawValuesSchema.json", "r")
    json_object_raw_sip_rate = json.load(json_file)
    json_file = open("NetFlow/Entropy/Schemas/RawValuesSchema.json", "r")
    json_object_raw_dip = json.load(json_file)
    json_file = open("NetFlow/Entropy/Schemas/RawValuesSchema.json", "r")
    json_object_raw_dip_rate = json.load(json_file)
    json_file = open("NetFlow/Entropy/Schemas/RawValuesSchema.json", "r")
    json_object_raw_f = json.load(json_file)
    json_file = open("NetFlow/Entropy/Schemas/RawValuesSchema.json", "r")
    json_object_raw_f_rate = json.load(json_file)
    json_file = open("NetFlow/Entropy/Schemas/RawValuesSchema.json", "r")
    json_object_raw_nf = json.load(json_file)
    json_file = open("NetFlow/Entropy/Schemas/RawValuesSchema.json", "r")
    json_object_raw_icmp_ratio = json.load(json_file)
    json_file = open("NetFlow/Entropy/Schemas/RawValuesSchema.json", "r")
    json_object_raw_icmp_packets = json.load(json_file)
    json_file.close()

    #Makes a datetime object of the input start time
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []
    
    #Instantiate counter variable
    i = 0
    sizes = []
    lastMinuteSize = 0

    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
        #Aggregate flows into the specified time interval
        if rec.stime >= startTime + interval:
            #Find the probability distribution based on how many packets there is in each source flow in this time interval
            PiSIP, ns = ipSourceDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropySip = generalizedEntropy(10,PiSIP)

            #Find the probability distribution based on how many packets there is in each destination flow in this time interval
            PiDIP, nd = ipDestinationDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyDip = generalizedEntropy(10,PiDIP)
            
            #Find the probability distribution based on how many packets there is in each bi-directional flow in this time interval
            PiF, nf = flowDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyFlow = generalizedEntropy(10, PiF)

            #Find the ratio of ICMP packets in this time interval
            icmpRatio, icmpPackets = icmpDistribution(records)

            json_object_raw_sip["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(entropySip)
            json_object_raw_sip_rate["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(entropySip/ns)
            json_object_raw_dip["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(entropyDip)
            json_object_raw_dip_rate["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(entropyDip/nd)
            json_object_raw_f["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(entropyFlow)
            json_object_raw_f_rate["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(entropyFlow/nf)
            json_object_raw_nf["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(nf)
            json_object_raw_icmp_ratio["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(icmpRatio)
            json_object_raw_icmp_packets["weekday"][rec.stime.strftime('%w')]["hour"][str(rec.stime.hour)]["minute"][str(rec.stime.minute)].append(icmpPackets)

            #Reset the record aggregation
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
        if rec.stime >= windowTime + frequency:
            thisMinuteSize = len(records) - lastMinuteSize
            sizes.append(thisMinuteSize)
            lastMinuteSize = thisMinuteSize
            windowTime += frequency
        records.append(rec)
    

    infile.close()
    json_file_raw_sip = open("NetFlow/Entropy/Calculations/sip."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json", "w")
    json.dump(json_object_raw_sip,json_file_raw_sip)
    json_file_raw_sip.close()

    json_file_raw_sip_rate = open("NetFlow/Entropy/Calculations/sip_rate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json", "w")
    json.dump(json_object_raw_sip_rate,json_file_raw_sip_rate)
    json_file_raw_sip_rate.close()

    json_file_raw_dip = open("NetFlow/Entropy/Calculations/dip."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json", "w")
    json.dump(json_object_raw_dip,json_file_raw_dip)
    json_file_raw_dip.close()

    json_file_raw_dip_rate = open("NetFlow/Entropy/Calculations/dip_rate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json", "w")
    json.dump(json_object_raw_dip_rate,json_file_raw_dip_rate)
    json_file_raw_dip_rate.close()

    json_file_raw_flow = open("NetFlow/Entropy/Calculations/flow."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json", "w")
    json.dump(json_object_raw_f,json_file_raw_flow)
    json_file_raw_flow.close()

    json_file_raw_f_rate = open("NetFlow/Entropy/Calculations/f_rate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json", "w")
    json.dump(json_object_raw_f_rate,json_file_raw_f_rate)
    json_file_raw_f_rate.close()

    json_file_raw_nf = open("NetFlow/Entropy/Calculations/nf."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json", "w")
    json.dump(json_object_raw_nf,json_file_raw_nf)
    json_file_raw_nf.close()

    json_file_raw_icmp_ratio = open("NetFlow/Entropy/Calculations/icmp_ratio."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json", "w")
    json.dump(json_object_raw_icmp_ratio,json_file_raw_icmp_ratio)
    json_file_raw_icmp_ratio.close()

    json_file_raw_icmp_packets = open("NetFlow/Entropy/Calculations/icmp_packets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json", "w")
    json.dump(json_object_raw_icmp_packets,json_file_raw_icmp_packets)
    json_file_raw_icmp_packets.close()
'''    
metricCalculation("/home/linneafg/silk-data/RawDataFromFilter/one-day-2011-01-10_11-sorted.rw", "2011-01-10 00:00:00", "2011-01-11 00:00:00",timedelta(minutes = 1), timedelta(minutes = 5))'''
silkFiles = ["/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week1.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week2.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week3.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week4.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week5.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week6.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week7.rw"]
start="2010-12-27 00:00:00"
stop="2011-01-03 00:00:00"

metricCalculation(silkFiles[0], start, stop, timedelta(minutes = 1), timedelta(minutes = 5))
metricCalculation(silkFiles[0], start, stop, timedelta(minutes = 1), timedelta(minutes = 10))