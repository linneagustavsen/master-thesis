from silk import *
import numpy as np

def ipDestinationDistribution(infile):
    numberOfPacketsPerIP ={}
    sumOfPackets = 0

    # Loop over the records in the file
    for rec in infile:
        if rec.dip in numberOfPacketsPerIP:
            numberOfPacketsPerIP[rec.dip] += rec.packets
        else:
            numberOfPacketsPerIP[rec.dip] = rec.packets
        sumOfPackets += rec.packets

    Pi = []
    
    for rec in infile:
        Pi.append(numberOfPacketsPerIP[rec.dip]/sumOfPackets)
    
    return Pi,sumOfPackets