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

    numberOfPacketsPerIP ={}
    sumOfPackets = 0

    # Loop over the records in the file
    for rec in infile:
        if rec.sip in numberOfPacketsPerIP:
            numberOfPacketsPerIP[rec.sip] += rec.packets
        else:
            numberOfPacketsPerIP[rec.sip] = rec.packets
        sumOfPackets += rec.packets

    Pi = []
    
    for rec in infile:
        Pi.append(numberOfPacketsPerIP[rec.sip]/sumOfPackets)
    
    return Pi,sumOfPackets