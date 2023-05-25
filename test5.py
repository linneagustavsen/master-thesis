
from Telemetry.Threshold.StatisticalModelCalculations import statisticalModelCalculations

start = "2023-03-08 08:00:00"
stop = "2023-03-08 10:00:00"
attackDate="08.03.23"
fields = ["egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets"]
bucket = "april"
statisticalModelCalculations(start, stop, "trd-gw", bucket, "egress_stats__if_1sec_pkts", attackDate)
