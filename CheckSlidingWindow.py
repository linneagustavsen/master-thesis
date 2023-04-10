from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta

def testingSlidingWindow(silkFile, start, stop, frequency, interval):    
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
            print("rec.stime:",rec.stime, "windowTime + frequency:", windowTime + frequency)
            lastSizes = 0
            print("Sizes:", sizes)
            for size in sizes:
                lastSizes += size
            print("lastSizes:", lastSizes)
            print("len(records):", len(records))
            thisMinuteSize = len(records) - lastSizes
            print("thisMinuteSize:", thisMinuteSize)
            sizes.append(thisMinuteSize)
            print("Sizes:", sizes)
            windowTime += frequency
        #Aggregate flows into the specified time interval
        if rec.stime >= startTime + interval:
            #Push the sliding window
            print("rec.stime:",rec.stime, "startTime + interval:", startTime + interval)
            startTime = startTime + frequency
            print("records:",records )
            records = records[sizes[0]:]
            print("records:",records )
            print("Sizes:", sizes)
            sizes.pop(0)
            print("Sizes:", sizes)
            i += 1

        records.append(rec)
    
    infile.close()
    
baseFile="two-hours-2011-01-02_10-11-sorted.rw"         
start = "2011-01-02 10:00:00"
stop = "2011-01-02 12:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 5)
pathToRawFiles="/home/linneafg/silk-data/RawDataFromFilter/"
###Threshold
silkFile = pathToRawFiles + baseFile
testingSlidingWindow(silkFile, start, stop, frequency, interval)