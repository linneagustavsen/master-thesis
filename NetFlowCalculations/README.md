Dependencies:
    numpy==1.24.1
    pandas==1.5.3
    scikit_learn==1.2.2
    silk==0.1


1. Get out the flows from the day of the attack. I used the following command:
    rwfilter --start-date=2023/03/08:08 --end-date=2023/03/08:19 --all-destination=stdout --data-rootdir=<PATH TO DATA FROM SYSTEM>/<SYSTEM NAME> (Ex: oslo-gw) | rwsort --fields=stime --output-path=<PATH TO RAW FILES>/<SYSTEM NAME>/twelve-hours-2023-03-08_08-20-sorted.rw

2. Get out flows with only SYN flag set:
	rwfilter --start-date=2023/03/08:08 --end-date=2023/03/08:19 --proto=6,56 --flags-all=S/SA --pass-destination=stdout --data-rootdir=<PATH TO DATA FROM SYSTEM>/<SYSTEM NAME> | rwsort --fields=stime --output-path=<PATH TO RAW FILES>/<SYSTEM NAME>/tcp-syn-twelve-hours-2023-03-08_08-20-sorted.rw

3. Get icmp packets with type "destination unreachable"
	rwfilter --start-date=2023/03/08:08 --end-date=2023/03/08:19 --proto=1,58 --icmp-type=3 --pass-destination=stdout --data-rootdir=<PATH TO DATA FROM SYSTEM>/<SYSTEM NAME> | rwsort --fields=stime --output-path=<PATH TO RAW FILES>/<SYSTEM NAME>/icmp3-twelve-hours-2023-03-08_08-20-sorted.rw 

4. Do step 1-3 for every system in this list:
        ["bergen-gw3", "hoytek-gw2", "hovedbygget-gw", "trd-gw", "teknobyen-gw2", "teknobyen-gw1", "ifi2-gw5", 
           "oslo-gw1", "tromso-gw5", "stangnes-gw", "rodbergvn-gw2", "narvik-kv-gw", "narvik-gw3", "tromso-fh-gw",
           "ma2-gw", "narvik-gw4"]

5. Look over main.py and make sure the paths to the raw files are correct

6. Run main.py

7. Transfer the NetFlowCalculations folder with the .csv files over to me
