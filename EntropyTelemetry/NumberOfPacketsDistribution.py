import numpy as np

def numberOfPacketsDistribution(dfEgressPackets):
    egressPackets = dfEgressPackets["_value"].to_numpy()
    
    Pi = []
    sumOfNP = sum(egressPackets)
    for value in egressPackets:
        Pi.append(value/sumOfNP)
    return Pi
    