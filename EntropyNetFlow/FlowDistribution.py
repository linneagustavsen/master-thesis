from silk import *

def flowDistribution(infile):
    numberOfPacketsPerFlow ={}
    flows= []
    sumOfPackets = 0
    for rec in infile:
        if (rec.sip,rec.dip) in flows:
            numberOfPacketsPerFlow[flows.index((rec.sip,rec.dip))] += rec.packets
        elif (rec.dip,rec.sip) in flows:
            numberOfPacketsPerFlow[flows.index((rec.dip,rec.sip))] += rec.packets
        else:
            flows.append((rec.sip,rec.dip))
            numberOfPacketsPerFlow[flows.index((rec.sip,rec.dip))] = rec.packets
        sumOfPackets += rec.packets
    
    Pi = []
    
    for rec in infile:
        if (rec.sip,rec.dip) in flows:
            Pi.append(numberOfPacketsPerFlow[flows.index((rec.sip,rec.dip))]/sumOfPackets)
        elif (rec.dip,rec.sip) in flows:
            Pi.append(numberOfPacketsPerFlow[flows.index((rec.dip,rec.sip))]/sumOfPackets)

    return Pi, len(flows)