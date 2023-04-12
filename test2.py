from datetime import timedelta
from NetFlow.Entropy.MetricCalculation import metricCalculation
silkFile = "/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-02_10-11-sorted.rw"
start = "2011-01-02 10:00:00"
stop = "2011-01-02 11:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 5)
systemId = "oslo-gw"
attackDate = "01.02"
metricCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
