from datetime import timedelta
from NetFlow.Entropy.MetricCalculation import metricCalculation
from NetFlow.Entropy.SYNEntropyCalculation import synEntropyCalculation
from NetFlow.Threshold.ICMPDstUnreachableCalculation import icmpDstUnreachableCalculation
from NetFlow.Threshold.SYNCalculation import synCalculation
from NetFlow.Threshold.XmasCalculation import xmasCalculation
from NetFlow.TopKFlows.topkflowCalculation import topkflows2

'''
    Function to get different calculations on NetFlow data
    Input:  baseFile:       string, raw base file with SiLK NetFlow records,
            systems:        list of strings, list of systems the calculations will be made on,
            start:          string, indicates the start time of the records,
            stop:           string, indicates the stop time of the records,
            frequency:      timedelta object, frequency of metric calculation,
            interval:       timedelta object, size of the sliding window which the calculation is made on,
            pathToRawFiles: string, path to the SiLK NetFlow records,
            attackDate:     string, date of the attack the calculations are made on
'''
def main(baseFile, systems, start, stop, frequency, interval, pathToRawFiles, attackDate):
    for systemId in systems:
        print(systemId)
        print(str(interval))
        silkFile = pathToRawFiles+systemId + "/"+ baseFile
        #Entropy and other metrics calculations
        metricCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
        print("Finished entropy and other metrics calculations")
        #Entropy of SYN calculation
        silkFileSyn = pathToRawFiles+systemId + "/tcp-syn-"+ baseFile
        synEntropyCalculation(silkFileSyn, start, stop, systemId, frequency, interval, attackDate)
        print("Finished entropy of SYN calculation")
        #ICMP unreachable calculation
        silkFileICMP3 = pathToRawFiles+systemId + "/icmp3-"+ baseFile
        icmpDstUnreachableCalculation(silkFileICMP3, start, stop, systemId, frequency, interval, attackDate)
        print("Finished icmp unreachable calculations")
        #SYN calculation
        synCalculation(silkFileSyn, start, stop, systemId, attackDate)
        print("Finished SYN calculations")
        #TopKflows
        topkflows2(silkFile, start, stop, frequency, 20, attackDate, systemId)
        print("Finished top k flows")
        xmasCalculation(silkFile, start, stop, systemId, attackDate)
        print("Finished Xmas calculation")

'''
    Function to get different calculations on NetFlow data
    This function only includes the metrics that depend on interval
    Input:  baseFile:       string, raw base file with SiLK NetFlow records,
            systems:        list of strings, systems the calculations will be made on,
            start:          string, indicates the start time of the records,
            stop:           string, indicates the stop time of the records,
            frequency:      timedelta object, frequency of metric calculation,
            interval:       timedelta object, size of the sliding window which the calculation is made on,
            pathToRawFiles: string, path to the SiLK NetFlow records,
            attackDate:     string, date of the attack the calculations are made on
'''
def main2(baseFile, systems, start, stop, frequency, interval, pathToRawFiles, attackDate):
    for systemId in systems:
        print(systemId)
        print(str(interval))
        silkFile = pathToRawFiles+systemId + "/"+ baseFile
        #Entropy and other metrics calculations
        metricCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
        print("Finished entropy and other metrics calculations")
        #Entropy of SYN calculation
        silkFileSyn = pathToRawFiles+systemId + "/tcp-syn-"+ baseFile
        synEntropyCalculation(silkFileSyn, start, stop, systemId, frequency, interval, attackDate)
        print("Finished entropy of SYN calculation")
        silkFileICMP3 = pathToRawFiles+systemId + "/icmp3-"+ baseFile
        icmpDstUnreachableCalculation(silkFileICMP3, start, stop, systemId, frequency, interval, attackDate)
        print("Finished icmp unreachable calculations")

#Attack number 2
baseFile="2023-03-17_11-14-sorted.rw"         
systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
start = "2023-03-17 11:00:00"
stop = "2023-03-17 14:00:00"

frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 5)
pathToRawFiles="/data/master-dump/fresh-netflow-data/master-dump/"
attackDate="17.03.23"

main(baseFile, systems, start, stop, frequency, interval, pathToRawFiles, attackDate)    

interval = timedelta(minutes = 10)
main2(baseFile, systems, start, stop, frequency, interval, pathToRawFiles, attackDate)

interval = timedelta(minutes = 15)
main2(baseFile, systems, start, stop, frequency, interval, pathToRawFiles, attackDate)

#Attack number 3
baseFile="2023-03-24_14-18-sorted.rw"         
systems = ["bergen-gw3", "hoytek-gw2", "hovedbygget-gw", "trd-gw", "teknobyen-gw2", "teknobyen-gw1", "ifi2-gw5", 
            "oslo-gw1", "tromso-gw5", "stangnes-gw", "rodbergvn-gw2", "narvik-kv-gw", "narvik-gw3", "tromso-fh-gw",
            "ma2-gw", "narvik-gw4"]
start = "2023-03-24 14:00:00"
stop = "2023-03-24 18:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 5)
pathToRawFiles="/data/master-dump/fresh-netflow-data/master-dump/"
attackDate="24.03.23"

main(baseFile, systems, start, stop, frequency, interval, pathToRawFiles, attackDate)       

interval = timedelta(minutes = 10)
main2(baseFile, systems, start, stop, frequency, interval, pathToRawFiles, attackDate)       

interval = timedelta(minutes = 15)
main2(baseFile, systems, start, stop, frequency, interval, pathToRawFiles, attackDate)