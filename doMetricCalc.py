from datetime import timedelta
from NetFlow.Entropy.Week1 import week1
from NetFlow.Entropy.Week2 import week2
from NetFlow.Entropy.Week3 import week3
from NetFlow.Entropy.Week4 import week4
from NetFlow.Entropy.Week5 import week5
from NetFlow.Entropy.Week6 import week6
from NetFlow.Entropy.Week7 import week7
silkFiles = ["/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week1.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week2.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week3.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week4.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week5.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week6.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week7.rw"]
start="2010-12-27 00:00:00"
stop="2011-01-03 00:00:00"
week1(silkFiles[0], start, stop, timedelta(minutes = 1), timedelta(minutes = 10))
start="2011-01-03 00:00:00"
stop="2011-01-10 00:00:00"
week2(silkFiles[1], start, stop, timedelta(minutes = 1), timedelta(minutes = 10))
start="2011-01-10 00:00:00"
stop="2011-01-17 00:00:00"
week3(silkFiles[2], start, stop, timedelta(minutes = 1), timedelta(minutes = 10))
start="2011-01-17 00:00:00"
stop="2011-01-24 00:00:00"
week4(silkFiles[3], start, stop, timedelta(minutes = 1), timedelta(minutes = 10))
start="2011-01-24 00:00:00"
stop="2011-01-31 00:00:00"
week5(silkFiles[4], start, stop, timedelta(minutes = 1), timedelta(minutes = 10))
start="2011-01-31 00:00:00"
stop="2011-02-07 00:00:00"
week6(silkFiles[5], start, stop, timedelta(minutes = 1), timedelta(minutes = 10))
start="2011-02-07 00:00:00"
stop="2011-02-14 00:00:00"
week7(silkFiles[6], start, stop, timedelta(minutes = 1), timedelta(minutes = 10))
