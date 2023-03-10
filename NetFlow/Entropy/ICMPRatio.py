'''

    Calculates the ratio of ICMP packets in a time interval

'''

def icmpRatio(records):
    icmpPackets = 0
    packets = 0

    #Loop through the flow records in a time interval
    for rec in records:
        #Check if the flow is an ICMP protocol
        #If it is we count up the packets in the flow
        if rec.protocol == 1 or rec.protocol == 58:
            icmpPackets += rec.packets
        else:
            packets += rec.packets

    #Return the ratio of ICMP packets to the number of packets of other protocols
    return icmpPackets/packets