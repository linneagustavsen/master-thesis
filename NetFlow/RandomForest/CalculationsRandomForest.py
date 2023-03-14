from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np

def randomForestCalculations(systemId):
    f = open("NetFlow/RandomForest/Calculations/Alerts."+ str(systemId) + ".csv", "a")
    f.write("Time,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,real_label")
    
    trainingSet = pd.read_pickle("NetFlow/RandomForest/RawData/TrainingSet."+str(systemId)+ ".pkl")
    trainingMeasurements = np.array(trainingSet.iloc[1:, 0:-1])
    print(trainingMeasurements)
    trainingLabel = np.array(trainingSet.iloc[1:,-1])

    classifier_RF = RandomForestClassifier(n_estimators = 100)
    classifier_RF.fit(trainingMeasurements,trainingLabel)

    testingSet = pd.read_pickle("NetFlow/RandomForest/RawData/TestingSet."+str(systemId)+ ".pkl")
    print(len(testingSet))
    timeStamps = pd.read_pickle("NetFlow/RandomForest/RawData/Testing."+str(systemId)+ ".pkl")["sTime"].to_numpy()

    testingMeasurements = np.array(testingSet.iloc[1:,  0:-1])
    testingLabel = np.array(testingSet.iloc[1:,-1])

    prediction = classifier_RF.predict(testingMeasurements)
    for i in range(len(prediction)):
        if prediction[i] == 1:
            f.write("\n"  + str(timeStamps[i]) + "," +str(testingMeasurements[i][2])+ "," +str(testingMeasurements[i][3])+"," +str(testingMeasurements[i][4])+ "," +str(testingMeasurements[i][5])+ "," +str(testingMeasurements[i][6])+ "," +str(testingMeasurements[i][7])+ "," +str(testingMeasurements[i][8]) + "," +str(testingMeasurements[i][9])+ "," +str(testingMeasurements[i][10])+ "," +str(testingMeasurements[i][11])+ "," +str(testingMeasurements[i][12])+ "," +str(testingMeasurements[i][13])+ "," +str(testingMeasurements[i][14])+ "," +str(testingMeasurements[i][15])+ "," +str(testingMeasurements[i][17])+ "," +str(testingMeasurements[i][18])+ "," +str(testingMeasurements[i][19])+ "," +str(testingMeasurements[i][20])+ "," +str(testingMeasurements[i][21])+ "," +str(testingMeasurements[i][22])+ "," +str(testingMeasurements[i][23])+ "," +str(testingMeasurements[i][24])+ "," +str(testingMeasurements[i][25])+ "," +testingLabel[i])
    print(prediction)

    f.close()
randomForestCalculations("oslo-gw")
