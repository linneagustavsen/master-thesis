'''

rwfilter --start-date=2011/01/01:10 --end-date=2011/01/01:11 --all-destination=/home/linneafg/silk-data/RawDataFromFilter/one-hour-2010-12-01_10-11.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw

'''

# Import the PySiLK bindings
from silk import *
from IPSourceDistribution import *
from GeneralizedEntropy import *

# Main function
def main(silkFile):

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    PiSIP, ns = ipSourceDistribution(infile)
    print(PiSIP)
    print(generalizedEntropy(10,PiSIP))
    print(generalizedEntropy(10,PiSIP)/ns)

    infile.close()

main("/home/linneafg/silk-data/RawDataFromFilter/one-hour-2010-12-01_10-11.rw")