'''

    have a set of flows
    need to group flows by IP source address (count how many packets each source ip has)
    These will be IP source flows
    pi: for every flow what is the probability that this IP source address is what it is
        current IP address/the number of flows with this ip source address
    

'''
from silk import *
import numpy as np

def ipSourceDistribution(infile):

    # Create an empty IPset
    sourceSet = IPSet()

    counter = 0

    recordIPs = []
    recordPackets = []
    # Loop over the records in the file
    for rec in infile:
        sourceSet.add(rec.sip)
        recordIPs.append(rec.sip)
        recordPackets.append(rec.packets)
        counter +=1
    print(sourceSet)
    
    uniqueIPs = len(sourceSet)
    ipAddrs = []
    for ip in sourceSet:
        ipAddrs.append(ip)
    
    numberOfPacketsPerIP = np.zeros(uniqueIPs)
    print(uniqueIPs, counter)

    print(infile)
    for i in range(len(recordIPs)):
        numberOfPacketsPerIP[ipAddrs.index(recordIPs[i])] += recordPackets[i]
        #STOPPED HERE NEED A SMALLER SET. FIND A WAY TO PARTITION IT INTO 5 MIN INTERVALS. CALL FUNCTION EVERY 5 MINUTES? COLLECT ALL RECORDS IN A LIST AND SEND THe list to the function when the stime is past 5 minutes
    
    Pi = []

    for i in range(len(recordIPs)):
        Pi.append(recordPackets[i]/numberOfPacketsPerIP[ipAddrs.index(recordIPs[i])])
    
    return Pi,uniqueIPs