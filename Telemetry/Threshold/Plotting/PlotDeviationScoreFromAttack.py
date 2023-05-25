import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates
import pandas as pd

'''
    Make a plot based on arrays of values and timestamps
'''
def makePlotDeviationScore(y_field, y_field_name, systemId, attackDate):
    data = pd.read_csv("Calculations/Threshold/Telemetry/"+ y_field+ ".attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
    
    y_values = data["Deviation_score"]

    if len(y_values) == 0:
        return

    timeAxis = pd.to_datetime(data["sTime"])
       
    fig, axs = plt.subplots(1, 1, figsize=(20, 5))
   
    axs.plot(timeAxis ,y_values, color="#162931")
    format = '%b %d %H:%M:%S'
    strings = [
            ["Mar 08 14:29:55", "Mar 08 14:34:56"], ["Mar 08 14:49:56", "Mar 08 15:02:57"],
            ["Mar 08 15:09:56", "Mar 08 15:17:02"], ["Mar 08 15:37:00", "Mar 08 15:52:02"]]
    attacks = ["SYN Flood", "SlowLoris", "Ping Flood", "R.U.D.Y"]
    colors = ["#CB997E","#DDBEA9", "#FFD5B5", "#B7B7A4"]
    '''strings = [["Mar 17 11:00:01", "Mar 17 11:07:02"], ["Mar 17 11:37:02", "Mar 17 11:50:04"],
           ["Mar 17 11:57:02", "Mar 17 12:04:12"], ["Mar 17 12:44:10", "Mar 17 13:00:17"]]
    attacks = ["SYN Flood", "SlowLoris", "Ping Flood", "R.U.D.Y"]
    colors = ["#CB997E","#DDBEA9", "#FFD5B5", "#B7B7A4"]'''
    '''strings = [["Mar 24 14:00:01", "Mar 24 14:03:57"], ["Mar 24 14:13:29", "Mar 24 14:29:08"],
           ["Mar 24 14:46:30", "Mar 24 14:55:00"], ["Mar 24 14:59:50", "Mar 24 15:15:06"], 
           ["Mar 24 15:26:51", "Mar 24 15:39:22"], ["Mar 24 15:40:21", "Mar 24 15:47:50"], 
           ["Mar 24 16:07:29", "Mar 24 16:19:00"], ["Mar 24 16:22:29", "Mar 24 16:29:13"],
           ["Mar 24 16:29:53", "Mar 24 16:49:50"], ["Mar 24 16:53:22", "Mar 24 17:09:39"],
           ["Mar 24 17:25:15", "Mar 24 17:47:00"]]
    attacks = ["UDP Flood", "SlowLoris", "Ping Flood", "Slow Read", "Blacknurse", "SYN Flood", "R.U.D.Y",
                "Xmas", "UDP Flood and SlowLoris", "Ping Flood and R.U.D.Y", "All types"]
    colors = ["#EDDCD2","#FFF1E6", "#FDE2E4", "#FAD2E1", "#C5DEDD", "#DBE7E4", "#F0EFEB", "#D6E2E9", "#BCD4E6","#A2C7E1", "#99C1DE"]'''
    counterStrings = 0
    for string in strings:
        start = datetime.strptime(string[0], format).replace(year=2023)
        stop = datetime.strptime(string[1], format).replace(year=2023)
        axs.axvspan(start, stop, facecolor=colors[counterStrings], label=attacks[counterStrings])
        counterStrings += 1
    
    axs.xaxis.set(
        major_locator=mdates.MinuteLocator(interval=30),
        major_formatter=mdates.DateFormatter("%H:%M"),
        
    )
    axs.set_title("Deviation scores for "+ y_field_name, fontsize=20)
    axs.set_xlabel('Time', fontsize=15)
    axs.set_ylabel("Deviation score", fontsize=15)
    axs.tick_params(axis='both', which='major', labelsize=12)
    fig.legend()
    fig.tight_layout()
    fig.savefig("Plots/Threshold/Attack0803/Telemetry/StatisticalModel/"+ y_field+ "."+ str(systemId)+ ".png", dpi=300)
    plt.close()


systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
y_fields = ["egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets"]
y_field_names = ["Current egress queue size", "Egress packets/s", "Egress bytes/s", "Ingress packets/s", "Ingress bytes/s"]
attackDate = "08.03.23"
for i in range(len(y_fields)):
    print(y_fields[i])
    for systemId in systems:
        print(systemId)
        makePlotDeviationScore(y_fields[i], y_field_names[i], systemId,  attackDate)
        break