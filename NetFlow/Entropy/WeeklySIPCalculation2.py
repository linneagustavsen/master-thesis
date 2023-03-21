'''
How to get the flows in a file format:

    #Filter out all flows from a time period
    rwfilter --start-date=2011/01/03:00 --end-date=2011/01/10:00 --all-destination=/home/linneafg/silk-data/RawDataFromFilter/one-week-2011-01-03_03-10.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw

    #Sorts them by start time
    rwsort --fields=stime --output-path=/home/linneafg/silk-data/RawDataFromFilter/one-week-2011-01-03_03-10-sorted.rw /home/linneafg/silk-data/RawDataFromFilter/one-week-2011-01-03_03-10.rw

'''

from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *

'''

    Calculates entropy and other metrics and write them to file. Also checks if the flow is an attack flow
    Input:  File with flow records sorted on time, 
            start time as a string, 
            an aggregation interval as a timedelta object, 
            a window size of how far back we should compare the values
'''

def weeklyMetricCalculation(silkFile, week):
    #Open file to write alerts to
    calculations = open("NetFlow/Entropy/Calculations/WeeklySIP.csv", "a")
    
    #Write the column titles to the files
    #calculations.write("Week,srcEntropy")
    
    print("Started on the silk files")
    
        
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    
    print("Start on silk file", week)
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
    print(PiSIP[0:10])
    print(len(PiSIP))
    entropySip = generalizedEntropy(10,PiSIP)
    
    print("Finished IP source calculation for silk file", week)

    print("Finished with silk file", week)
    calculations.write("\n" + str(week) + "," + str(entropySip))

    infile.close()
    calculations.close()
     
silkFiles = ["/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week1.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week2.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week3.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week4.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week5.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week6.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week7.rw"]
weeklyMetricCalculation(silkFiles[1],2)

