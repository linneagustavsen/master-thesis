from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *

'''
    Calculates entropy and other metrics and write them to file. Also checks if the flow is an attack flow
    Input:  silkFile:   string, File with flow records sorted on time, 
            week:       int, what week number this calculation is for
'''
def weeklyMetricCalculation(silkFile, week):
    #Open file to write alerts to
    calculations = open("NetFlow/Entropy/Calculations/WeeklySIP.csv", "a")
    
    #Write the column titles to the files
    calculations.write("Week,srcEntropy")
  
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Make dictionaries for how many packets each destination flow has
    numberOfPacketsPerSIP ={}
    #A variable to keep track of the total amount of packets in this time interval
    sumOfPacketsSIP = 0
    #Loop through each flow record in the time interval
    for rec in infile:
        #If the current flow has the same source IP as a previous flow the number of packets is added to the record of that source IP
        #If it has not been encountered before it is added to the dictionary
        if rec.sip in numberOfPacketsPerSIP:
            numberOfPacketsPerSIP[rec.sip] += rec.packets
        else:
            numberOfPacketsPerSIP[rec.sip] = rec.packets
        sumOfPacketsSIP += rec.packets

    #Array to keep track of the probability distribution
    PiSIP = []
    infile.close()
    infile = silkfile_open(silkFile, READ)
    #Loop through each flow record in the time interval
    for rec in infile:
        #Add the probability of the current source flow having the size that it does to the distribution
        PiSIP.append(numberOfPacketsPerSIP[rec.sip]/sumOfPacketsSIP)
        
    #Calculate the generalized entropy of this distribution
    entropySip = generalizedEntropy(10,PiSIP)
    
    calculations.write("\n" + str(week) + "," + str(entropySip))

    infile.close()
    calculations.close()
     
silkFiles = ["/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week1.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week2.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week3.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week4.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week5.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week6.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week7.rw"]
weeklyMetricCalculation(silkFiles[0],1)

