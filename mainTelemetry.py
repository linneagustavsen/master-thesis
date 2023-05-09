#Attack 1
from datetime import datetime, timedelta
import math
import os

from Telemetry.Entropy.EntropyCalculation import calculationEntropyTelemetry
from Telemetry.Kmeans.CalculationsKmeansCombined import calculationsKmeansCombinedTelemetry
from Telemetry.Kmeans.CalculationsKmeansEntropy import calculationsKmeansEntropyTelemetry
from Telemetry.Kmeans.CalculationsKmeansFields import calculationsKmeansFieldsTelemetry
from Telemetry.RandomForest.CalculationRFCombined import calculationsRandomForestTelemetryCombined
from Telemetry.RandomForest.CalculationRFEntropy import calculationsRandomForestTelemetryEntropy
from Telemetry.RandomForest.CalculationRFFields import calculationsRandomForestFieldsTelemetry
from Telemetry.RandomForest.MakeDataSetCombined import makeDataSetRandomForestCombinedTelemetry
from Telemetry.RandomForest.MakeDataSetEntropy import makeDataSetTelemetryEntropy
from Telemetry.RandomForest.MakeDataSetFields import makeDataSetTelemetryFields
from Telemetry.Threshold.StatisticalModelCalculations import statisticalModelCalculations

def main(start, stop, startKmeans, stopKmeans, systems, bucket, fields, intervals, frequency,clusterFrequency, attackDate):
    for systemId in systems:
        print("On router:", systemId)
        
        calculationsKmeansFieldsTelemetry(startKmeans, stopKmeans, systemId, bucket, clusterFrequency, fields, attackDate)
        print("Finished with calculationsKmeansFieldsTelemetry")
        
        '''for field in fields:
            statisticalModelCalculations(start, stop, systemId, bucket, field, attackDate)
            print("Finished with statisticalModelCalculations for field", field)

        for interval in intervals:
            if interval == timedelta(minutes=15):
                clusterFrequency = timedelta(minutes=30)
            print("On interval", str(interval))

            calculationEntropyTelemetry(start, stop, systemId, interval, frequency, attackDate)
            print("Finished with calculationEntropyTelemetry")
            
            calculationsKmeansEntropyTelemetry(startKmeans, stopKmeans, systemId, bucket, interval, frequency, attackDate)
            print("Finished with calculationsKmeansEntropyTelemetry")
            
            calculationsKmeansCombinedTelemetry(startKmeans, stopKmeans, systemId, bucket, interval, frequency, clusterFrequency, fields, attackDate)
            print("Finished with calculationsKmeansCombinedTelemetry")
            
        
            if os.path.exists("Telemetry/Kmeans/DataSets/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"):
                os.remove("Telemetry/Kmeans/DataSets/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
            else:
                print("The file Telemetry/Kmeans/DataSets/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl does not exist") 

        startTime = datetime.strptime(startKmeans, '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime(stopKmeans, '%Y-%m-%d %H:%M:%S')
        intervalTime = (stopTime - startTime).total_seconds()/timedelta(minutes=15).total_seconds()
    
        for i in range(math.ceil(intervalTime)):
            stopTime = startTime + timedelta(minutes=15)
            if os.path.exists("Telemetry/Kmeans/DataSets/Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".pkl"):
                os.remove("Telemetry/Kmeans/DataSets/Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".pkl")
            else:
                print("The file Telemetry/Kmeans/DataSets/Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".pkl does not exist") 
            startTime += timedelta(minutes=15)'''
        

def randomForestMain(startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, systems, bucket, fields, intervals, frequency, attackDate):
    for systemId in systems: 
        print("On router:", systemId)
  
        makeDataSetTelemetryFields(startRFTraining, stopRFTraining, bucket, fields, systemId, "Training", attackDate)
        makeDataSetTelemetryFields(startRFTesting, stopRFTesting, bucket, fields, systemId, "Testing", attackDate)
        calculationsRandomForestFieldsTelemetry(systemId, attackDate)
        print("Finished with calculationsRandomForestFieldsTelemetry")

        for interval in intervals:
            print("On interval", str(interval))
            makeDataSetTelemetryEntropy(startRFTraining, stopRFTraining, systemId, bucket, frequency, interval, "Training", attackDate)
            makeDataSetTelemetryEntropy(startRFTesting, stopRFTesting, systemId, bucket, frequency, interval, "Testing", attackDate)
            calculationsRandomForestTelemetryEntropy(systemId, interval, attackDate)
            print("Finished with calculationsRandomForestTelemetryEntropy")
            
            makeDataSetRandomForestCombinedTelemetry(startRFTraining, stopRFTraining, systemId, bucket, fields, interval, frequency, "Training", attackDate)
            makeDataSetRandomForestCombinedTelemetry(startRFTesting, stopRFTesting, systemId, bucket, fields, interval, frequency, "Testing", attackDate)
            calculationsRandomForestTelemetryCombined(systemId, interval, attackDate)
            print("Finished with calculationsRandomForestTelemetryCombined")

            if os.path.exists("Telemetry/RandomForest/DataSets/Training/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"):
                os.remove("Telemetry/RandomForest/DataSets/Training/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
            else:
                print("The file Telemetry/RandomForest/DataSets/Training/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl does not exist") 

            if os.path.exists("Telemetry/RandomForest/DataSets/Testing/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"):
                os.remove("Telemetry/RandomForest/DataSets/Testing/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
            else:
                print("The file Telemetry/RandomForest/DataSets/Testing/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl does not exist") 

            if os.path.exists("Telemetry/RandomForest/DataSets/Training/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"):
                os.remove("Telemetry/RandomForest/DataSets/Training/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy")
            else:
                print("The file Telemetry/RandomForest/DataSets/Training/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy does not exist") 

            if os.path.exists("Telemetry/RandomForest/DataSets/Testing/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"):
                os.remove("Telemetry/RandomForest/DataSets/Testing/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy")
            else:
                print("The file Telemetry/RandomForest/DataSets/Testing/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy does not exist") 
        
        if os.path.exists("Telemetry/RandomForest/DataSets/Testing/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"):
            os.remove("Telemetry/RandomForest/DataSets/Testing/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy")
        else:
            print("The file Telemetry/RandomForest/DataSets/Testing/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy does not exist") 

        
systems = ["narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]

start = "2023-03-08 08:00:00"
stop = "2023-03-08 20:00:00"
startRFTraining = "2023-03-08 14:00:00"
stopRFTraining = "2023-03-08 15:00:00"
startRFTesting = "2023-03-08 15:00:00"
stopRFTesting = "2023-03-08 16:00:00"
startKmeans = "2023-03-08 14:00:00"
stopKmeans= "2023-03-08 16:00:00"
frequency = timedelta(minutes = 1)
intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
clusterFrequency = timedelta(minutes = 15)
attackDate="08.03.23"
fields = ["egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets"]
bucket = "april"
#main(start, stop, startKmeans, stopKmeans, systems, bucket, fields, intervals, frequency,clusterFrequency, attackDate)
randomForestMain(startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, systems, bucket, fields, intervals, frequency, attackDate)