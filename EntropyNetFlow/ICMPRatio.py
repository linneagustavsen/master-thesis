def icmpRatio(records):
    icmpPackets = 0
    packets = 0

    for rec in records:
        if rec.protocol == 1 or rec.protocol == 58:
            icmpPackets += rec.packets
        packets += rec.packets

    return icmpPackets/packets