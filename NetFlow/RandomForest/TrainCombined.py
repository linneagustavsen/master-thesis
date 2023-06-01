from pathlib import Path
import pickle
from sklearn.ensemble import RandomForestClassifier
import numpy as np
from HelperFunctions.StructureData import structureDataNumpyArrays

def trainCombined(systemId, interval, attackDate, estimator):
    datasetsPath = Path('NetFlow')
    modelPath = datasetsPath / 'RandomForest' / 'Models'
    if not modelPath.exists():
        modelPath.mkdir(parents=True)
    filename = str(modelPath) + "/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"
    if not Path(filename).exists():
        dsPath = datasetsPath / 'RandomForest' / 'DataSets'

        with open(str(dsPath) + "/Training/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'rb') as trainingFile:
            trainingSet = np.load(trainingFile, allow_pickle=True)
        
        if len(trainingSet) ==0:
            return 
        
        trainingsTime, trainingeTime, trainingMeasurements, trainingLabel = structureDataNumpyArrays(trainingSet)    
        trainingLabel=trainingLabel.astype('int')  
        
        classifier_RF = RandomForestClassifier(n_estimators = estimator)
        classifier_RF.fit(trainingMeasurements,trainingLabel)

        pickle.dump(classifier_RF, open(filename, 'wb'))

def trainCombinedNoIP(systemId, interval, attackDate, estimator):
    datasetsPath = Path('NetFlow')
    modelPath = datasetsPath / 'RandomForest' / 'Models'
    if not modelPath.exists():
        modelPath.mkdir(parents=True)
    filename = str(modelPath) + "/CombinedNoIP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl" 
    
    if not Path(filename).exists():
        dsPath = datasetsPath / 'RandomForest' / 'DataSets'
        fieldsFile = str(dsPath) + "/Training/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"
        fieldsFileNoIP = str(dsPath) + "/Training/CombinedNoIP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"
        if Path(fieldsFileNoIP).exists():
            with open(str(fieldsFileNoIP), 'rb') as trainingFile:
                trainingSet = np.load(trainingFile, allow_pickle=True)
        elif Path(fieldsFile).exists():
            with open(str(fieldsFile), 'rb') as trainingFile:
                df0 = np.load(trainingFile, allow_pickle=True)
            if len(df0) ==0:
                return 
            df1 = np.delete(df0, np.s_[2:4],1)
            trainingSet = np.delete(df1, 16,1)

        trainingsTime, trainingeTime, trainingMeasurements, trainingLabel = structureDataNumpyArrays(trainingSet)    
        trainingLabel=trainingLabel.astype('int')  

        classifier_RF = RandomForestClassifier(n_estimators = estimator)
        classifier_RF.fit(trainingMeasurements,trainingLabel)

        pickle.dump(classifier_RF, open(filename, 'wb'))