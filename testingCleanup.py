from datetime import timedelta
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
from NetFlow.RandomForest.MakeDataSet import makeDataSetNetFlow, makeDataSetNoIPNetFlow
from NetFlow.RandomForest.RandomForestDetection import detectionRandomForestNetFlow, detectionRandomForestNoIPNetFlow
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
thresholdGeneration(systemId, if_name, field, start, stop)
start = "2022-09-21 01:00:00"
stop = "2022-09-22 00:00:00"
detectionBytesTelemetry(start, stop, systemId, if_name, interval, frequency, windowSize, thresholdBytes, attackDate)
detectionTelemetry(systemId, if_name, field, start, stop, threshold, attackDate)
detectionMaxVar(start, stop, systemId, if_name, field, attackDate)
detectionPacketsTelemetry(start, stop, systemId, if_name, interval, frequency, windowSize, thresholdPackets, attackDate)

###Random forest
path = "Training"
trainingSet = makeDataSetRandomForestTelemetry(systemId, if_name, start, stop, interval, frequency, path, attackDate)
path = "Testing"
testingSet = makeDataSetRandomForestTelemetry(systemId, if_name, start, stop, interval, frequency, path, attackDate)
detectionRandomForestTelemetry(trainingSet, testingSet, systemId, interval, attackDate)
calculationsRandomForestTelemetry(trainingSet, testingSet, systemId, interval, attackDate)

###K-means
testingSet = makeDataSetKmeansTelemetry(systemId, if_name, start, stop, interval, frequency, path, attackDate)
kmeansGraphEntropy(start, stop, systemId, if_name, interval, frequency, attackDate)
kmeansGraphCombined(testingSet, systemId, interval, attackDate)
fields = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets"]
kmeansGraph(start, stop, systemId, if_name, fields, attackDate)
detectionKmeansEntropyTelemetry(start, stop, systemId, if_name, interval, frequency, attackDate)
detectionKmeansCombinedTelemetry(testingSet, systemId, if_name, attackDate)
detectionKmeansTelemetry(start, stop, systemId, if_name, fields, attackDate)

###Entropy
calculationEntropyTelemetry(start, stop, systemId, if_name, interval, frequency, attackDate)
detectionEntropyTelemetry(start, stop, systemId, if_name, interval, frequency, windowSize, thresholdEntropy, thresholdEntropyRate, thresholdPackets, thresholdBytes, attackDate)


baseFile="two-hours-2011-01-02_10-11-sorted.rw"         
system = "oslo-gw"
start = "2011-01-02 10:00:00"
stop = "2011-01-02 12:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 5)
pathToRawFiles="/home/linneafg/silk-data/RawDataFromFilter/"
attackDate="02.01"
###Threshold
silkFile = pathToRawFiles + baseFile
synDetection(silkFile, start, stop, systemId, windowSize, threshold, attackDate)
synCalculation(silkFile, start, stop, systemId, attackDate)
detectionPacketsNetFlow(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdPackets, attackDate)
threshold = 50
icmpDstUnreachableDetection(silkFile, start, stop, systemId, frequency, interval, windowSize, threshold, attackDate)
icmpDstUnreachableCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
thresholdICMPRatio = 0.01
thresholdNumberOfICMPPackets = 600
detectionICMP(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdICMPRatio, thresholdNumberOfICMPPackets, attackDate)
detectionBytesNetFlow(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdBytes, attackDate)

###Random Forest
path = "Training"
trainingSet = makeDataSetNetFlow(silkFile, start, stop, systemId, frequency, interval, path, attackDate)
path = "Testing"
testingSet = makeDataSetNetFlow(silkFile, start, stop, systemId, frequency, interval, path, attackDate)
detectionRandomForestNetFlow(trainingSet, testingSet, systemId, interval, attackDate)

path = "Training"
trainingSet = makeDataSetNoIPNetFlow(silkFile, start, stop, systemId, frequency, interval, path, attackDate)
path = "Testing"
testingSet = makeDataSetNoIPNetFlow(silkFile, start, stop, systemId, frequency, interval, path, attackDate)
detectionRandomForestNoIPNetFlow(trainingSet, testingSet, systemId, interval, attackDate)

###K-means
testingSet = makeDataSetKmeansNetFlow(silkFile, start, stop, systemId, frequency, interval, attackDate)
kmeansEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
kmeansCombinedCalculation(testingSet, systemId, interval, attackDate)
kmeansCalculation(silkFile, start, stop, systemId, attackDate)

###Entropy
thresholdSrc =  4
thresholdDst =  4
thresholdFlow = 4
synEntropyDetection(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdSrc, thresholdDst, thresholdFlow, attackDate)
synEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
thresholdSrcEntropy =  4
thresholdSrcEntropyRate = 0.0002
detectionSrc(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdSrcEntropy, thresholdSrcEntropyRate, attackDate)
thresholdPSEntropy = 4 
thresholdPSEntropyRate = 0.0002
detectionPS(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdPSEntropy, thresholdPSEntropyRate, attackDate)
metricCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
thresholdFlowEntropy = 3
thresholdFlowEntropyRate = 0.0002
thresholdNumberOfFlows = 60000
detectionFlow(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdFlowEntropy, thresholdFlowEntropyRate, thresholdNumberOfFlows, attackDate)
thresholdDstEntropy =  4
thresholdDstEntropyRate = 0.0002
detectionDst(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdDstEntropy, thresholdDstEntropyRate, attackDate)
detection(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdSrcEntropy, thresholdSrcEntropyRate, thresholdDstEntropy, thresholdDstEntropyRate, thresholdFlowEntropy, thresholdFlowEntropyRate, thresholdNumberOfFlows, thresholdICMPRatio, thresholdNumberOfICMPPackets, thresholdPSEntropy, thresholdPSEntropyRate, thresholdPackets, thresholdBytes, attackDate)