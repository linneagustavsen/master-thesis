from sklearn.metrics import davies_bouldin_score
from sklearn.metrics.pairwise import euclidean_distances
def labelCluster(measurements, predictions, DBthreshold, c1threshold, c2threshold):
    db = davies_bouldin_score(measurements, predictions)
    cd1 = 0

def centroidDiameter(X, predictions, cluster):
    counter = 0
    sumOfMeasurements = []
    for k in range(len(predictions)):
        if predictions[k] == cluster:
            counter += 1
            for i in range(len(X[k])):
                sumOfMeasurements[i] += X[k]
    
    sc = sumOfMeasurements/counter

    sumOfDistances = 0
    for k in range(len(predictions)):
        if predictions[k] == cluster:
            sumOfDistances[0] += euclidean_distances(X[k], sc)
    
    centroidDiameter = 2*sumOfDistances/counter
    return centroidDiameter