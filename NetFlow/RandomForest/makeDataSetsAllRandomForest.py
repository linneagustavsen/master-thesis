

from datetime import timedelta
from pathlib import Path
import pickle

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from MakeDataSet import makeDataSetNetFlow, makeDataSetNoIPNetFlow
from MakeDataSetEntropy import makeDataSetNetFlowEntropy
from MakeDataSetFields import makeDataSetNetFlowFields, makeDataSetNoIPNetFlowFields


def makeDataSetsAndTrain(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, pathToRawFiles, attackDate):
    for systemId in systems:
        trainingFile = pathToRawFiles+systemId + "/"+ trainingBase
        testingFile = pathToRawFiles+systemId + "/"+ testingBase
        
        p = Path('NetFlow')
        q = p / 'RandomForest' / 'DataSets'
        trainingPath = q / 'Training'
        testingPath = q / 'Testing'
        if not trainingPath.exists():
            trainingPath.mkdir(parents=True)
        if not testingPath.exists():
            testingPath.mkdir(parents=True)

        #trainingSet = makeDataSetNetFlow(trainingFile, startRFTraining, stopRFTraining, systemId, frequency, interval, "Training", attackDate)        
        #testingSet = makeDataSetNetFlow(testingFile, startRFTesting, stopRFTesting, systemId, frequency, interval, "Testing", attackDate)
        #trainingSet.to_pickle(str(trainingPath) + "/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
        #testingSet.to_pickle(str(testingPath) + "/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
        '''
        trainingMeasurements = np.array(trainingSet.iloc[:, 0:-1])
        trainingLabel = np.array(trainingSet.iloc[:,-1])

        #Initialize a RF classifier and fit it to the training data set
        classifier_RF = RandomForestClassifier(n_estimators = 100)
        classifier_RF.fit(trainingMeasurements, trainingLabel)
        '''
        modelPath = p / 'RandomForest' / 'Models'
        if not modelPath.exists():
            modelPath.mkdir(parents=True)
        #filename = str(modelPath) + "/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"
        #pickle.dump(classifier_RF, open(filename, 'wb'))
        
        trainingSet = makeDataSetNoIPNetFlow(trainingFile, startRFTraining, stopRFTraining, systemId, frequency, interval, "Training", attackDate)
        trainingSet.to_pickle(str(trainingPath) + "/CombinedNoIP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
        testingSet = makeDataSetNoIPNetFlow(testingFile, startRFTesting, stopRFTesting, systemId, frequency, interval, "Testing", attackDate)
        testingSet.to_pickle(str(testingPath) + "/CombinedNoIP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
        

        trainingMeasurements = np.array(trainingSet.iloc[:, 0:-1])
        trainingLabel = np.array(trainingSet.iloc[:,-1])

        #Initialize a RF classifier and fit it to the training data set
        classifier_RF = RandomForestClassifier(n_estimators = 100)
        classifier_RF.fit(trainingMeasurements, trainingLabel)

        filename = str(modelPath) + "/CombinedNoIP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"
        pickle.dump(classifier_RF, open(filename, 'wb'))

        trainingSet = makeDataSetNetFlowEntropy(trainingFile, startRFTraining, stopRFTraining, systemId, frequency, interval, "Training", attackDate)
        trainingSet.to_pickle(str(trainingPath) + "/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
        testingSet = makeDataSetNetFlowEntropy(testingFile, startRFTesting, stopRFTesting, systemId, frequency, interval, "Testing", attackDate)
        testingSet.to_pickle(str(testingPath) + "/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")

        trainingMeasurements = np.array(trainingSet.iloc[:, 0:-1])
        trainingLabel = np.array(trainingSet.iloc[:,-1])

        #Initialize a RF classifier and fit it to the training data set
        classifier_RF = RandomForestClassifier(n_estimators = 100)
        classifier_RF.fit(trainingMeasurements, trainingLabel)

        filename = str(modelPath) + "/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"
        pickle.dump(classifier_RF, open(filename, 'wb'))

        trainingSet = makeDataSetNetFlowFields(trainingFile, startRFTraining, stopRFTraining, systemId, "Training", attackDate)
        trainingSet.to_pickle(str(trainingPath) + "/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
        testingSet = makeDataSetNetFlowFields(testingFile, startRFTesting, stopRFTesting, systemId, "Testing", attackDate)
        testingSet.to_pickle(str(testingPath) + "/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")

        trainingMeasurements = np.array(trainingSet.iloc[:, 0:-1])
        trainingLabel = np.array(trainingSet.iloc[:,-1])

        #Initialize a RF classifier and fit it to the training data set
        classifier_RF = RandomForestClassifier(n_estimators = 100)
        classifier_RF.fit(trainingMeasurements, trainingLabel)

        filename = str(modelPath) + "/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"
        pickle.dump(classifier_RF, open(filename, 'wb'))

        trainingSet = makeDataSetNoIPNetFlowFields(trainingFile, startRFTraining, stopRFTraining, systemId, "Training", attackDate)
        trainingSet.to_pickle(str(trainingPath) + "/FieldsNoIP.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
        testingSet = makeDataSetNoIPNetFlowFields(testingFile, startRFTesting, stopRFTesting, systemId, "Testing", attackDate)
        testingSet.to_pickle(str(testingPath) + "/FieldsNoIP.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")

        trainingMeasurements = np.array(trainingSet.iloc[:, 0:-1])
        trainingLabel = np.array(trainingSet.iloc[:,-1])

        #Initialize a RF classifier and fit it to the training data set
        classifier_RF = RandomForestClassifier(n_estimators = 100)
        classifier_RF.fit(trainingMeasurements, trainingLabel)

        filename = str(modelPath) + "/FieldsNoIP.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"
        pickle.dump(classifier_RF, open(filename, 'wb'))

trainingBase="twelve-hours-2011-01-01_08-20-sorted.rw"
testingBase="two-hours-2011-02-08_10-12-sorted.rw"
startRFTraining = "2011-01-01 10:00:00"
stopRFTraining = "2011-01-01 15:00:00"
systems = ["oslo-gw1"]


baseFile="two-hours-2011-02-08_10-12-sorted.rw"         
systemId = "oslo-gw1"
startRFTesting = "2011-02-08 10:00:00"
stopRFTesting = "2011-02-08 12:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 10)
pathToRawFiles="/home/linneafg/silk-data/RawDataFromFilter/"
attackDate="08.02.11"
silkFile = pathToRawFiles+systemId + "/"+ baseFile
makeDataSetsAndTrain(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, pathToRawFiles, attackDate)