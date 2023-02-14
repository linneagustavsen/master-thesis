def numberOfPackets(records):
    np = 0

    for rec in records:
        np+= rec.packets

    return np