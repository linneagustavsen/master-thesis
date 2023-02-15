'''
    #Get icmp packets with destination AS 224 in the oslo-gw:
	rwfilter --start-date=2011/01/03:00 --end-date=2011/01/10:00 --proto=6,56 --flags-all=S/SA --pass-destination=/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw
	
    #Sorts them by start time
	rwsort --fields=stime --output-path=/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in-sorted.rw  /home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in.rw 

'''

# Import the PySiLK bindings
from silk import *
from MakePlot import *
from SYNPacketDistribution import *
from GeneralizedEntropy import *
from datetime import datetime, timedelta

def synDetection(silkFile):

    #startTime = datetime.strptime("2010-12-26 06:00:00", '%Y-%m-%d %H:%M:%S')
    startTime = datetime.strptime("2011-01-03 00:00:00", '%Y-%m-%d %H:%M:%S')
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    records = []

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    synPacketsPerFlow = []

    timeArray = []
    for rec in infile:
        if rec.packets >= 5:
            synPacketsPerFlow.append(rec.packets)
            #send out alert that packets in a syn flow has preceded a threshold of 5
            print("More than 5 packets in a flow at time:", rec.stime)
        else:
            synPacketsPerFlow.append(None)
        timeArray.append(None)
       

    infile.close()

    '''makePlot(synPacketsPerFlow, timeArray, "Number of syn packets per flow")
    
  '''
synDetection("/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in-sorted.rw")
#synDetection("/home/linneafg/silk-data/RawDataFromFilter/tcpSyn-in-sorted-time.rw")