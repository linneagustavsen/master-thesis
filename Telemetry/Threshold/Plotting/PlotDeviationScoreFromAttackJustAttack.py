import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates
import pandas as pd

'''
    Make a plot based on arrays of values and timestamps
'''
def makePlotDeviationScore(y_field, y_field_name, systemId, attackDate):
    if attackDate == "08.03.23":
        fileString = "0803"
        strings = [
            ["Mar 08 14:29:55", "Mar 08 14:34:56"], ["Mar 08 14:49:56", "Mar 08 15:02:57"],
            ["Mar 08 15:09:56", "Mar 08 15:17:02"], ["Mar 08 15:37:00", "Mar 08 15:52:02"]]
        attacks = ["SYN Flood", "SlowLoris", "Ping Flood", "R.U.D.Y"]
        colors = ["#CB997E","#DDBEA9", "#99958C", "#B7B7A4", "#7F6A93"]
        start = datetime.strptime("2023-03-08 14:15:00", '%Y-%m-%d %H:%M:%S')
        stop = datetime.strptime("2023-03-08 16:00:00", '%Y-%m-%d %H:%M:%S')
    elif attackDate == "17.03.23":
        fileString = "1703"
        strings = [["Mar 17 11:00:01", "Mar 17 11:07:02"], ["Mar 17 11:37:02", "Mar 17 11:50:04"],
           ["Mar 17 11:57:02", "Mar 17 12:04:12"], ["Mar 17 12:44:10", "Mar 17 13:00:17"]]
        attacks = ["SYN Flood", "SlowLoris", "Ping Flood", "R.U.D.Y"]
        colors = ["#CB997E","#DDBEA9", "#99958C", "#B7B7A4", "#7F6A93"]
        start = datetime.strptime("2023-03-17 11:00:00", '%Y-%m-%d %H:%M:%S')
        stop = datetime.strptime("2023-03-17 13:00:00", '%Y-%m-%d %H:%M:%S')
    elif attackDate == "24.03.23":
        fileString = "2403"
        strings = [["Mar 24 14:00:01", "Mar 24 14:03:57"], ["Mar 24 14:13:29", "Mar 24 14:29:08"],
           ["Mar 24 14:46:30", "Mar 24 14:55:00"], ["Mar 24 14:59:50", "Mar 24 15:15:06"], 
           ["Mar 24 15:26:51", "Mar 24 15:39:22"], ["Mar 24 15:40:21", "Mar 24 15:47:50"], 
           ["Mar 24 16:07:29", "Mar 24 16:19:00"], ["Mar 24 16:22:29", "Mar 24 16:29:13"],
           ["Mar 24 16:29:53", "Mar 24 16:49:50"], ["Mar 24 16:53:22", "Mar 24 17:09:39"],
           ["Mar 24 17:25:15", "Mar 24 17:47:00"]]
        attacks = ["UDP Flood", "SlowLoris", "Ping Flood", "Slow Read", "Blacknurse", "SYN Flood", "R.U.D.Y",
                "Xmas", "UDP Flood\nand SlowLoris", "Ping Flood\nand R.U.D.Y", "All types"]
        colors = ['#CABBB1','#BDAA9D','#AD9585','#997B66','#D08C60',"#DAA684",'#FFC876','#F1DCA7','#D9AE94','#9B9B7A','#797D62', "#7F6A93"]
        start = datetime.strptime("2023-03-24 14:00:00", '%Y-%m-%d %H:%M:%S')
        stop = datetime.strptime("2023-03-24 18:00:00", '%Y-%m-%d %H:%M:%S')
    data = pd.read_csv("Calculations"+ fileString+ "/Threshold/Telemetry/"+ y_field+ ".attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
    
    y_values = data["Deviation_score"]
    sTime = pd.to_datetime(data["sTime"])
    eTime =  pd.to_datetime(data["eTime"])
    if len(y_values) == 0:
        return

    timeAxis = []
    values = []
    for i in range(len(sTime)):
        if eTime[i].replace(tzinfo=None) > stop:
            break
        if sTime[i].replace(tzinfo=None) < start:
            continue
        timeAxis.append(sTime[i])
        values.append(y_values[i])

       
    fig, axs = plt.subplots(1, 1, figsize=(20, 6))
    #axs.set_facecolor("lightgrey")
    axs.plot(timeAxis ,values, color="#162931")
    format = '%b %d %H:%M:%S'
    
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
    axs.set_xlabel('Time', fontsize=20)
    axs.set_ylabel("Deviation score", fontsize=20)
    axs.tick_params(axis='both', which='major', labelsize=15)
    fig.legend(fontsize=20)
    #fig.tight_layout()
    fig.savefig("Plots/Threshold/Attack"+ fileString+ "/Telemetry/StatisticalModel/JustAttack."+ y_field+ "."+ str(systemId)+ ".png", dpi=500)
    plt.close(fig)


systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
y_fields = ["egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets", "MaxVar.egress_queue_info__0__cur_buffer_occupancy", "MaxVar.egress_stats__if_1sec_pkts", "MaxVar.egress_stats__if_1sec_octets", "MaxVar.ingress_stats__if_1sec_pkts", "MaxVar.ingress_stats__if_1sec_octets"]
y_field_names = ["current egress queue size", "egress packets/s", "egress bytes/s", "ingress packets/s", "ingress bytes/s", "current egress queue size", "egress packets/s", "egress bytes/s", "ingress packets/s", "ingress bytes/s"]
attackDates =  ["08.03.23","17.03.23"]

systems = ["narvik-gw4", "hoytek-gw2"]
y_fields = ["egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets", "MaxVar.egress_stats__if_1sec_pkts", "MaxVar.egress_stats__if_1sec_octets", "MaxVar.ingress_stats__if_1sec_pkts", "MaxVar.ingress_stats__if_1sec_octets"]
y_field_names = [ "egress packets/s", "egress bytes/s", "ingress packets/s", "ingress bytes/s", "egress packets/s", "egress bytes/s", "ingress packets/s", "ingress bytes/s"]

attackDates =  ["08.03.23", "17.03.23", "24.03.23"]
for attackDate in attackDates:
    for i in range(len(y_fields)):
        for systemId in systems:
            makePlotDeviationScore(y_fields[i], y_field_names[i], systemId,  attackDate)
