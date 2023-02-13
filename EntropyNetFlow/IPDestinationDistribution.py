from silk import *
import numpy as np

def ipDestinationDistribution(infile):

    # Create an empty IPset
    destinationSet = IPSet()

    # Loop over the records in the file
    for rec in infile:
        destinationSet.add(rec.dip)

    uniqueIPs = len(destinationSet)
    ipAddrs = []

    for ip in destinationSet:
        ipAddrs.append(ip)
    
    numberOfPacketsPerIP = np.zeros(uniqueIPs)

    for rec in infile:
        numberOfPacketsPerIP[ipAddrs.index(rec.dip)] += rec.packets
        
    
    Pi = []
    sumOfPackets = sum(numberOfPacketsPerIP)

    for rec in infile:
        Pi.append(numberOfPacketsPerIP[ipAddrs.index(rec.dip)]/sumOfPackets)
    
    return Pi,sumOfPackets