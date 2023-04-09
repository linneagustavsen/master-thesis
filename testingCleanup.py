from datetime import timedelta
from NetFlow.RandomForest.CalculationsRandomForestEntropy import calculationRandomForestNetFlowEntropy
from NetFlow.RandomForest.CalculationsRandomForestFields import calculationRandomForestNetFlowFields, calculationRandomForestNoIPNetFlowFields
from NetFlow.RandomForest.MakeDataSetFields import makeDataSetNetFlowFields, makeDataSetNoIPNetFlowFields
from NetFlow.RandomForest.RandomForestDetection import detectionRandomForestNetFlowFields, detectionRandomForestNoIPNetFlowFields
from NetFlow.RandomForest.RandomForestDetectionEntropy import detectionRandomForestNetFlowEntropy
from NetFlow.Entropy.Detection import detection
from NetFlow.Entropy.DstDetection import detectionDst
from NetFlow.Entropy.FlowDetection import detectionFlow
from NetFlow.Entropy.MetricCalculation import metricCalculation
from NetFlow.Entropy.PacketSizeDetection import detectionPS
from NetFlow.Entropy.SYNEntropyCalculation import synEntropyCalculation
from NetFlow.Entropy.SYNEntropyDetection import synEntropyDetection
from NetFlow.Entropy.SrcDetection import detectionSrc
from NetFlow.Kmeans.CalculationsKmeans import kmeansCalculation
from NetFlow.Kmeans.CalculationsKmeansCombined import kmeansCombinedCalculation
from NetFlow.Kmeans.CalculationsKmeansEntropy import kmeansEntropyCalculation
from NetFlow.Kmeans.MakeDataSet import makeDataSetKmeansNetFlow
from NetFlow.RandomForest.CalculationsRandomForest import calculationsRandomForestNetFlow, calculationsRandomForestNoIPNetFlow
from NetFlow.RandomForest.MakeDataSet import makeDataSetNetFlow, makeDataSetNoIPNetFlow
from NetFlow.RandomForest.MakeDataSetEntropy import makeDataSetNetFlowEntropy
from NetFlow.RandomForest.RandomForestDetectionCombined import detectionRandomForestNetFlow, detectionRandomForestNoIPNetFlow
from NetFlow.Threshold.BytesDetection import detectionBytesNetFlow
from NetFlow.Threshold.ICMPDetection import detectionICMP
from NetFlow.Threshold.ICMPDstUnreachableCalculation import icmpDstUnreachableCalculation
from NetFlow.Threshold.ICMPDstUnreachableDetection import icmpDstUnreachableDetection
from NetFlow.Threshold.PacketsDetection import detectionPacketsNetFlow
from NetFlow.Threshold.SYNCalculation import synCalculation
from NetFlow.Threshold.SYNDetection import synDetection
from Telemetry.Entropy.Detection import detectionEntropyTelemetry
from Telemetry.Entropy.EntropyCalculation import calculationEntropyTelemetry
from Telemetry.Kmeans.Detection import detectionKmeansTelemetry
from Telemetry.Kmeans.DetectionCombined import detectionKmeansCombinedTelemetry
from Telemetry.Kmeans.DetectionEntropy import detectionKmeansEntropyTelemetry
from Telemetry.Kmeans.Graph import kmeansGraph
from Telemetry.Kmeans.GraphCombined import kmeansGraphCombined
from Telemetry.Kmeans.GraphEntropy import kmeansGraphEntropy
from Telemetry.Kmeans.MakeDataSet import makeDataSetKmeansTelemetry
from Telemetry.RandomForest.CalculationRF import calculationsRandomForestTelemetry
from Telemetry.RandomForest.DetectionRF import  detectionRandomForestTelemetry
from Telemetry.RandomForest.MakeDataSet import makeDataSetRandomForestTelemetry
from Telemetry.Threshold.BytesDetection import detectionBytesTelemetry
from Telemetry.Threshold.Detection import detectionTelemetry
from Telemetry.Threshold.DetectionMaxVar import detectionMaxVar
from Telemetry.Threshold.PacketsDetection import detectionPacketsTelemetry
from Telemetry.Threshold.ThresholdGeneration import thresholdGeneration

start = "2022-09-22 00:00:00"
stop = "2022-10-13 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"
interval = timedelta(minutes = 5)
frequency = timedelta(minutes = 1)
attackDate = "21.09"
windowSize = 10
thresholdEntropy = 0.5
thresholdEntropyRate = 0.005
thresholdPackets = 1000
thresholdBytes = 1000
threshold = 5
field = "egress_stats__if_1sec_pkts"
###Threshold
#thresholdGeneration(systemId, if_name, field, start, stop)
print("Finished thresholdGeneration")
start = "2022-10-05 00:00:00"
stop = "2022-10-06 00:00:00"
#detectionBytesTelemetry(start, stop, systemId, if_name, interval, frequency, windowSize, thresholdBytes, attackDate)
print("Finished detectionBytesTelemetry")
#detectionTelemetry(systemId, if_name, field, start, stop, threshold, attackDate)
print("Finished detectionTelemetry")
#detectionMaxVar(systemId, if_name, field, start, stop, threshold, attackDate)
print("Finished detectionMaxVar")
#detectionPacketsTelemetry(start, stop, systemId, if_name, interval, frequency, windowSize, thresholdPackets, attackDate)
print("Finished detectionPacketsTelemetry")

###Random forest
path = "Training"
#trainingSet = makeDataSetRandomForestTelemetry(systemId, if_name, start, stop, interval, frequency, path, attackDate)
print("Finished makeDataSetRandomForestTelemetry training")
path = "Testing"
#testingSet = makeDataSetRandomForestTelemetry(systemId, if_name, start, stop, interval, frequency, path, attackDate)
print("Finished makeDataSetRandomForestTelemetry testing")
#detectionRandomForestTelemetry(trainingSet, testingSet, systemId, interval, attackDate)
print("Finished detectionRandomForestTelemetry")
#calculationsRandomForestTelemetry(trainingSet, testingSet, systemId, interval, attackDate)
print("Finished calculationsRandomForestTelemetry")

###K-means
#testingSet = makeDataSetKmeansTelemetry(systemId, if_name, start, stop, interval, frequency, path, attackDate)
print("Finished makeDataSetKmeansTelemetry")
#kmeansGraphEntropy(start, stop, systemId, if_name, interval, frequency, attackDate)
print("Finished kmeansGraphEntropy")
#kmeansGraphCombined(testingSet, systemId, interval, attackDate)
print("Finished kmeansGraphCombined")
fields = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets"]
#kmeansGraph(start, stop, systemId, if_name, fields, attackDate)
print("Finished kmeansGraph")
#detectionKmeansEntropyTelemetry(start, stop, systemId, if_name, interval, frequency, attackDate)
print("Finished detectionKmeansEntropyTelemetry")
#detectionKmeansCombinedTelemetry(testingSet, systemId, if_name, attackDate)
print("Finished detectionKmeansCombinedTelemetry")
#detectionKmeansTelemetry(start, stop, systemId, if_name, fields, attackDate)
print("Finished detectionKmeansTelemetry")

###Entropy
#calculationEntropyTelemetry(start, stop, systemId, if_name, interval, frequency, attackDate)
print("Finished calculationEntropyTelemetry")
#detectionEntropyTelemetry(start, stop, systemId, if_name, interval, frequency, windowSize, thresholdEntropy, thresholdEntropyRate, thresholdPackets, thresholdBytes, attackDate)
print("Finished detectionEntropyTelemetry")

baseFile="two-hours-2011-01-02_10-11-sorted.rw"         
systemId = "oslo-gw"
start = "2011-01-02 10:00:00"
stop = "2011-01-02 12:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 5)
pathToRawFiles="/home/linneafg/silk-data/RawDataFromFilter/"
attackDate="02.01"
###Threshold
silkFile = pathToRawFiles + baseFile
#synDetection(silkFile, start, stop, systemId, windowSize, threshold, attackDate)
print("Finished synDetection")
#synCalculation(silkFile, start, stop, systemId, attackDate)
print("Finished synCalculation")
#detectionPacketsNetFlow(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdPackets, attackDate)
print("Finished detectionPacketsNetFlow")
threshold = 50
#icmpDstUnreachableDetection(silkFile, start, stop, systemId, frequency, interval, windowSize, threshold, attackDate)
print("Finished icmpDstUnreachableDetection")
#icmpDstUnreachableCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
print("Finished icmpDstUnreachableCalculation")
thresholdICMPRatio = 0.01
thresholdNumberOfICMPPackets = 600
#detectionICMP(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdICMPRatio, thresholdNumberOfICMPPackets, attackDate)
print("Finished detectionICMP")
#detectionBytesNetFlow(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdBytes, attackDate)
print("Finished detectionBytesNetFlow")

###Random Forest
#Combined
path = "Training"
#trainingSet = makeDataSetNetFlow(silkFile, start, stop, systemId, frequency, interval, path, attackDate)
print("Finished makeDataSetNetFlow training")
path = "Testing"
#testingSet = makeDataSetNetFlow(silkFile, start, stop, systemId, frequency, interval, path, attackDate)
print("Finished makeDataSetNetFlow testing")
#detectionRandomForestNetFlow(trainingSet, testingSet, systemId, interval, attackDate)
print("Finished detectionRandomForestNetFlow")
#calculationsRandomForestNetFlow(trainingSet, testingSet, systemId, interval, attackDate)
print("Finished calculationsRandomForestNetFlow")

#Combined No IP
path = "Training"
#trainingSet = makeDataSetNoIPNetFlow(silkFile, start, stop, systemId, frequency, interval, path, attackDate)
print("Finished makeDataSetNoIPNetFlow training")
path = "Testing"
#testingSet = makeDataSetNoIPNetFlow(silkFile, start, stop, systemId, frequency, interval, path, attackDate)
print("Finished makeDataSetNoIPNetFlow testing")
#detectionRandomForestNoIPNetFlow(trainingSet, testingSet, systemId, interval, attackDate)
print("Finished detectionRandomForestNoIPNetFlow")
#calculationsRandomForestNoIPNetFlow(trainingSet, testingSet, systemId, interval, attackDate)
print("Finished calculationsRandomForestNoIPNetFlow")

#Entropy
path = "Training"
trainingSet = makeDataSetNetFlowEntropy(silkFile, start, stop, systemId, frequency, interval, path, attackDate)
print("Finished makeDataSetNetFlowEntropy training")
path = "Testing"
testingSet = makeDataSetNetFlowEntropy(silkFile, start, stop, systemId, frequency, interval, path, attackDate)
print("Finished makeDataSetNetFlowEntropy testing")
detectionRandomForestNetFlowEntropy(trainingSet, testingSet, systemId, interval, attackDate)
print("Finished detectionRandomForestNetFlowEntropy")
calculationRandomForestNetFlowEntropy(trainingSet, testingSet, systemId, interval, attackDate)
print("Finished calculationRandomForestNetFlowEntropy")

#Fields
path = "Training"
trainingSet = makeDataSetNetFlowFields(silkFile, start, stop, systemId, path, attackDate)
print("Finished makeDataSetNetFlow training")
path = "Testing"
testingSet = makeDataSetNetFlowFields(silkFile, start, stop, systemId, path, attackDate)
print("Finished makeDataSetNetFlow testing")
detectionRandomForestNetFlowFields(trainingSet, testingSet, systemId, attackDate)
print("Finished detectionRandomForestNetFlowEntropy")
calculationRandomForestNetFlowFields(trainingSet, testingSet, systemId, attackDate)
print("Finished calculationRandomForestNetFlowFields")

#Fields no IP
path = "Training"
trainingSet = makeDataSetNoIPNetFlowFields(silkFile, start, stop, systemId, path, attackDate)
print("Finished makeDataSetNoIPNetFlow training")
path = "Testing"
testingSet = makeDataSetNoIPNetFlowFields(silkFile, start, stop, systemId, path, attackDate)
print("Finished makeDataSetNoIPNetFlow testing")
detectionRandomForestNoIPNetFlowFields(trainingSet, testingSet, systemId, attackDate)
print("Finished detectionRandomForestNoIPNetFlowFields")
calculationRandomForestNoIPNetFlowFields(trainingSet, testingSet, systemId, attackDate)
print("Finished calculationRandomForestNoIPNetFlowFields")

###K-means
testingSet = makeDataSetKmeansNetFlow(silkFile, start, stop, systemId, frequency, interval, attackDate)
print("Finished makeDataSetKmeansNetFlow")
kmeansEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
print("Finished kmeansEntropyCalculation")
kmeansCombinedCalculation(testingSet, systemId, interval, attackDate)
print("Finished kmeansCombinedCalculation")
kmeansCalculation(silkFile, start, stop, systemId, attackDate)
print("Finished kmeansCalculation")

###Entropy
thresholdSrc =  4
thresholdDst =  4
thresholdFlow = 4
synEntropyDetection(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdSrc, thresholdDst, thresholdFlow, attackDate)
print("Finished synEntropyDetection")
synEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
print("Finished synEntropyCalculation")
thresholdSrcEntropy =  4
thresholdSrcEntropyRate = 0.0002
detectionSrc(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdSrcEntropy, thresholdSrcEntropyRate, attackDate)
print("Finished detectionSrc")
thresholdPSEntropy = 4 
thresholdPSEntropyRate = 0.0002
detectionPS(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdPSEntropy, thresholdPSEntropyRate, attackDate)
print("Finished detectionPS")
metricCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
print("Finished metricCalculation")
thresholdFlowEntropy = 3
thresholdFlowEntropyRate = 0.0002
thresholdNumberOfFlows = 60000
detectionFlow(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdFlowEntropy, thresholdFlowEntropyRate, thresholdNumberOfFlows, attackDate)
print("Finished detectionFlow")
thresholdDstEntropy =  4
thresholdDstEntropyRate = 0.0002
detectionDst(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdDstEntropy, thresholdDstEntropyRate, attackDate)
print("Finished detectionDst")
detection(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdSrcEntropy, thresholdSrcEntropyRate, thresholdDstEntropy, thresholdDstEntropyRate, thresholdFlowEntropy, thresholdFlowEntropyRate, thresholdNumberOfFlows, thresholdICMPRatio, thresholdNumberOfICMPPackets, thresholdPSEntropy, thresholdPSEntropyRate, thresholdPackets, thresholdBytes, attackDate)
print("Finished detection")