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
    calculations = open("NetFlow/Entropy/Calculations/WeeklyFlow.csv", "a")
    
    
    #Write the column titles to the files
    #calculations.write("Week,flowEntropy")
    
    
    #Instantiate counter variable
    i = 0
    print("Started on the silk files")
    #Loop through all the flow records in the input file
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    
    print("Start on silk file", week)
    #Make dictionaries for how many packets each destination flow has
    numberOfPacketsPerFlow = {}
    flows = {}
    #A variable to keep track of the total amount of packets in this time interval
    sumOfPackets = 0
    
    #Loop through each flow record in the time interval
    for rec in infile:
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
        sumOfPackets += rec.packets
    #Array to keep track of the probability distribution

    PiF = []
    infile.close()
    infile = silkfile_open(silkFile, READ)
    #Loop through each flow record in the time interval
    for rec in infile:
        flow = (rec.sip, rec.dip)
        reverse_flow = (rec.dip, rec.sip)
        if flow in flows:
            index = flows[flow]
        elif reverse_flow in flows:
            index = flows[reverse_flow]
        #Add the probability of the current flow having the size that it does to the distribution
        PiF.append(numberOfPacketsPerFlow[index]/sumOfPackets)

    #Calculate the generalized entropy of this distribution
    print(PiF[0:10])
    print(len(PiF))
    entropyFlow = generalizedEntropy(10, PiF)
    print("Finished flow calculation for silk file", i)


    print("Finished with silk file", week)
    calculations.write("\n" + str(week) + "," + str(entropyFlow))

    i += 1
    infile.close()
    calculations.close()
     
silkFiles = ["/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week1.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week2.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week3.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week4.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week5.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week6.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week7.rw"]
weeklyMetricCalculation(silkFiles[5],6)

