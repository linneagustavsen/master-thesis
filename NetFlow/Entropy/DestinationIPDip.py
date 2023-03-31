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
from datetime import datetime,timedelta
import json

'''

    Calculates entropy and other metrics and write them to file. Also checks if the flow is an attack flow
    Input:  File with flow records sorted on time, 
            start time as a string, 
            an aggregation interval as a timedelta object, 
            a window size of how far back we should compare the values
'''

def metricCalculation(silkFile, start, stop, interval):
    #Makes a datetime object of the input start time
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []
    
    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
        #Aggregate flows into the specified time interval
        if rec.stime >= startTime + interval:
            #Make dictionaries for how many packets each destination flow has
            numberOfPacketsPerIP ={}

            #Loop through each flow record in the time interval
            for rec in records:
                #If the current flow has the same destination IP as a previous flow the number of packets is added to the record of that destination IP
                #If it has not been encountered before it is added to the dictionary
                if rec.dip in numberOfPacketsPerIP:
                    numberOfPacketsPerIP[rec.dip] += rec.packets
                else:
                    numberOfPacketsPerIP[rec.dip] = rec.packets
            print(numberOfPacketsPerIP)    
            records = []
        records.append(rec)
    

    infile.close()

silkFiles = ["/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week1.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week2.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week3.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week4.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week5.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week6.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week7.rw"]
start="2011-01-17 00:00:00"
stop="2011-01-24 00:00:00"

metricCalculation(silkFiles[3], start, stop, timedelta(minutes = 1))