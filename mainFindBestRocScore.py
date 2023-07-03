from datetime import timedelta
import json
from operator import itemgetter
from Telemetry.Entropy.findBestRocScore import findBestRocScore

start = "2023-03-24 14:00:00"
stop = "2023-03-24 18:00:00"
intervals = [timedelta(seconds=5),timedelta(seconds=10), timedelta(seconds=20), timedelta(seconds=30), timedelta(seconds=40), timedelta(seconds=50)]
for i in range(1,11):
    intervals.append(timedelta(minutes=i))

frequencies = []
for i in range(1,180, 5):
    frequencies.append(timedelta(seconds=i))

findBestRocScore(start, stop, "teknobyen-gw1", frequencies, intervals, range(2,40), range(2,20))


'''json_file = open("ThresholdDecision/Entropy/Telemetry/AUC_pr.json", "r")
auc_pr = json.load(json_file)
new_auc_scores =sorted(auc_pr["Number of egress packets"].items(), key=itemgetter(1), reverse=True)[:10]
print(new_auc_scores)'''