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

    # Loop over the records in the file
    for rec in infile:
        sourceSet.add(rec.sip)
    
    uniqueIPs = len(sourceSet)
    ipAddrs = []
    for ip in sourceSet:
        ipAddrs.append(ip)
    
    numberOfPacketsPerIP = np.zeros(uniqueIPs)

    for rec in infile:
        numberOfPacketsPerIP[ipAddrs.index(rec.sip)] += rec.packets

    Pi = []
    sumOfPackets = sum(numberOfPacketsPerIP)
    
    for rec in infile:
        Pi.append(numberOfPacketsPerIP[ipAddrs.index(rec.sip)]/sumOfPackets)
    
    return Pi,sumOfPackets