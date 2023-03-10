from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np

trainingSet = pd.read_pickle("Telemetry/RandomForest/Data/TrainingSet.pkl")

valueArrayX = np.array(trainingSet.iloc[1:, 0:5])
print(valueArrayX)
labely = np.array(trainingSet.iloc[1:,6])

classifier_RF = RandomForestClassifier(n_estimators = 100)
classifier_RF.fit(valueArrayX,labely)

testingSet = pd.read_pickle("Telemetry/RandomForest/Data/TestingSet.pkl")
print(len(testingSet))

X_test = np.array(testingSet.iloc[1:,  0:5])
y_test = np.array(testingSet.iloc[1:,6])

pred_RF_teste = classifier_RF.predict(X_test)
for i in range(len(pred_RF_teste)):
    if pred_RF_teste[i] == 1:
        print("One alert at index:", i)
print(pred_RF_teste)