#Attack 1
from datetime import datetime, timedelta
from Telemetry.Entropy.GetPacketSizeDistribution import getPacketSizeDistribution

def main(start, stop, systems, bucket, fields, intervals, frequency, attackDate):
    for systemId in systems:
        print("On router:", systemId)
        
        for interval in intervals:
            print("On interval", str(interval))

            getPacketSizeDistribution(start, stop, systemId, interval, frequency, attackDate)
            print("Finished with getPacketSizeDistribution")

systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]


#Attack 2
start = "2023-03-17 11:00:00"
stop = "2023-03-17 14:00:00"
frequency = timedelta(minutes = 1)
intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
attackDate= "17.03.23"
fields = ["egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets"]
bucket = "april"
main(start, stop, systems, bucket, fields, intervals, frequency, attackDate)

#Attack 3
start = "2023-03-24 14:00:00"
stop = "2023-03-24 18:00:00"
attackDate="24.03.23"
main(start, stop, systems, bucket, fields, intervals, frequency, attackDate)
