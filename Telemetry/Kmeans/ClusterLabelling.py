from sklearn.metrics import davies_bouldin_score
from sklearn.metrics.pairwise import euclidean_distances
import numpy as np

def labelCluster(measurements, predictions, DBthreshold, c0threshold, c1threshold):
    db = davies_bouldin_score(measurements, predictions)

    n_features = measurements.shape[1]

    counter0 = np.count_nonzero(predictions == 0)
    counter1 = np.count_nonzero(predictions == 1)

    sumOfMeasurements0 = np.zeros(n_features)
    sumOfMeasurements1 = np.zeros(n_features)
    indices0 = np.where(predictions == 0)[0]
    indices1 = np.where(predictions == 1)[0]

    sumOfMeasurements0 = np.sum(measurements[indices0], axis=0)
    sumOfMeasurements1 = np.sum(measurements[indices1], axis=0)

    sc0 = sumOfMeasurements0 / counter0
    sc1 = sumOfMeasurements1 / counter1

    distances0 = euclidean_distances(measurements[indices0], [sc0])
    distances1 = euclidean_distances(measurements[indices1], [sc1])

    cd0 = 2*np.sum(distances0)/counter0
    cd1 = 2*np.sum(distances1)/counter1

    attackCluster = 1
    #If it is a burst attack and c1 is empty, c0 is the attack cluster
    if db == 0 and cd1 == 0:
        attackCluster = 0
    #If there is no burst and c0 is less compact than c1, c0 is the attack cluster
    elif db > DBthreshold and cd0 > (cd1 + c0threshold):
        attackCluster = 0
    #If there is burst traffic and normal traffic and c1 is less compact than c0, c1 is the attack cluster
    elif db < DBthreshold and cd1 > (cd0 + c1threshold):
        attackCluster = 0

    return attackCluster, db, cd0, cd1, counter0, counter1
