from silk import *

def flowDistribution(infile):
    numberOfPacketsPerFlow = {}
    flows = {}
    sumOfPackets = 0
    for rec in infile:
        flow = (rec.sip, rec.dip)
        reverse_flow = (rec.dip, rec.sip)
        if flow in flows:
            index = flows[flow]
        elif reverse_flow in flows:
            index = flows[reverse_flow]
            flow = reverse_flow
        else:
            index = len(flows)
            flows[flow] = index
            numberOfPacketsPerFlow[index] = 0
        numberOfPacketsPerFlow[index] += rec.packets
        sumOfPackets += rec.packets
    
    Pi = []
    for rec in infile:
        flow = (rec.sip, rec.dip)
        reverse_flow = (rec.dip, rec.sip)
        if flow in flows:
            index = flows[flow]
        elif reverse_flow in flows:
            index = flows[reverse_flow]
        Pi.append(numberOfPacketsPerFlow[index]/sumOfPackets)

    return Pi, len(flows)
