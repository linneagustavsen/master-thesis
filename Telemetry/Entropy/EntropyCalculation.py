from datetime import datetime,timedelta
from pathlib import Path
import pickle
import numpy as np
from HelperFunctions.GetData import *
from HelperFunctions.GeneralizedEntropy import *
from HelperFunctions.Distributions import *
from HelperFunctions.IsAttack import isAttack
from HelperFunctionsTelemetry.GetDataTelemetry import getData, getDataBytes, getDataPackets

'''
    Calculates entropy and writes calculations to file
    Input:  start:      string, indicating the start time of the data to detect on
            stop:       string, indicating the stop time of the data to detect on
            systemId:   string, name of the system to collect and calculate on  
            if_name:    string, interface name, 
            interval:   timedelta object, size of the sliding window which the calculation is made on,
            frequency:  timedelta object, frequency of metric calculation,
            attackDate: string, date of the attack the calculations are made on
'''

def calculationEntropyTelemetry(start, stop, systemId, interval, frequency, attackDate):
    p = Path('Calculations')
    q = p / 'Entropy' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)
    #Open file to write alerts to
    calculations = open(str(q) + "/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #Write the column titles to the files
    calculations.write("sTime,eTime,entropy_packet_size_ingress,entropy_rate_packet_size_ingress,numberOfPackets_ingress,numberOfBytes_ingress,entropy_packet_size_egress,entropy_rate_packet_size_egress,numberOfPackets_egress,numberOfBytes_egress,real_label")

    #Instantiate empty arrays for the calculated values
    packetSizeArrayin = []
    packetSizeRateArrayin = []
    packetSizeArrayout = []
    packetSizeRateArrayout = []
    packetNumberArrayin = []
    bytesArrayin = []
    packetNumberArrayout = []
    bytesArrayout = []
    packetSizeDistributionDictin ={}
    packetSizeDistributionDictout ={}

    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    intervalTime = (stopTime - startTime).total_seconds()/frequency.total_seconds()
    j = 0
    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + interval
        #Get data for a specified time interval
        df_bytes_ingress = getDataBytes(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "april", systemId, "in")
        df_bytes_egress = getDataBytes(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "april", systemId, "out")
        df_packets_ingress = getDataPackets(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "april", systemId, "in")
        df_packets_egress = getDataPackets(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "april", systemId, "out")
        #If there is no data for this interval we skip the calculations
        if df_bytes_ingress.empty or df_packets_ingress.empty or df_bytes_egress.empty or df_packets_egress.empty:
            startTime = startTime + frequency
            continue
        df_bytes_ingress = df_bytes_ingress["bytes"].to_numpy()
        df_packets_ingress = df_packets_ingress["packets"].to_numpy()
        df_bytes_egress = df_bytes_egress["bytes"].to_numpy()
        df_packets_egress = df_packets_egress["packets"].to_numpy()


        #Find the probability distribution based on how big the packets are this time interval
        PiPS,nps,packetSizeDistributionDictArray = packetSizeDistributionDetection(df_bytes_ingress, df_packets_ingress)
        #Calculate the generalized entropy of this distribution
        entropyPacketSize = generalizedEntropy(10, PiPS)
        packetSizeArrayin.append(entropyPacketSize)
        #Calculate the generalized entropy rate of this distribution
        packetSizeRateArrayin.append(entropyPacketSize/nps)
        packetSizeDistributionDictin[stopTime.strftime("%Y-%m-%dT%H:%M:%SZ")] = packetSizeDistributionDictArray
        
        #Find the probability distribution based on how big the packets are this time interval
        PiPS,nps,packetSizeDistributionDictArray = packetSizeDistributionDetection(df_bytes_egress, df_packets_egress)
        #Calculate the generalized entropy of this distribution
        entropyPacketSize = generalizedEntropy(10, PiPS)
        packetSizeArrayout.append(entropyPacketSize)
        #Calculate the generalized entropy rate of this distribution
        packetSizeRateArrayout.append(entropyPacketSize/nps)
        packetSizeDistributionDictout[stopTime.strftime("%Y-%m-%dT%H:%M:%SZ")] = packetSizeDistributionDictArray

        #Store the number of packets and bytes this time interval
        packetNumberArrayin.append(sum(df_packets_ingress))
        bytesArrayin.append(sum(df_bytes_ingress))

        packetNumberArrayout.append(sum(df_packets_egress))
        bytesArrayout.append(sum(df_bytes_egress))
        if j == 0:
            sTime = startTime
        else:
            sTime =stopTime - frequency
            
        #If there is not enough stored values to compare with we skip the detection
        calculations.write("\n" + sTime.strftime("%Y-%m-%dT%H:%M:%SZ")+ ","+ stopTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(packetSizeArrayin[j]) + "," + str(packetSizeRateArrayin[j])
                               + "," + str(packetNumberArrayin[j]) + "," + str(bytesArrayin[j]) +  ","+ str(packetSizeArrayout[j]) + "," + str(packetSizeRateArrayout[j])
                               + "," + str(packetNumberArrayout[j]) + "," + str(bytesArrayout[j]) +  ","+ str(int(isAttack(sTime, stopTime))))

        #Push the start time by the specified frequency
        startTime = startTime + frequency
        j += 1

    calculations.close()

    distributionFile = open(str(q) + "/packetSizeDistributions_ingress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", "wb")
    pickle.dump(packetSizeDistributionDictin,distributionFile)
    distributionFile.close()

    distributionFile = open(str(q) + "/packetSizeDistributions_egress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", "wb")
    pickle.dump(packetSizeDistributionDictout,distributionFile)
    distributionFile.close()