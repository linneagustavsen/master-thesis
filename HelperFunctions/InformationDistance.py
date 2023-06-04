import math

'''
    Calculates the information distance between two probability distributions
    Input:  
            alpha:  int, the alpha
            Pi:     list of floats, probabilities of a distribution
            Qi:     list of floats, probabilities of a distribution
    Output:
                    float, Information distance
'''
def informationDistance(alpha, numberOfPacketsOfSizePi, numberOfPacketsOfSizeQi):
    Qi = []
    Pi = []
    sumOfP = 0
    sumOfQ = 0
    #Loop through each packet size in the time interval
    for key, value in numberOfPacketsOfSizePi.items():
        if key in numberOfPacketsOfSizeQi:
            #Add the probability of the current packet size having the size that it does to the distribution
            Pi.append(value)
            sumOfP += value
            Qi.append(numberOfPacketsOfSizeQi[key])
            sumOfQ += numberOfPacketsOfSizeQi[key]

    if len(Pi) == 0 or len(Qi) == 0:
        return 100000000000
    Pi = [x / sumOfP for x in Pi]
    Qi = [x / sumOfQ for x in Qi]

    sum1 = 0
    sum2 = 0
    
    for i in range(len(Qi)):
        sum1 += (Pi[i]**alpha)*(Qi[i]**(1-alpha))
        sum2 += (Qi[i]**alpha)*(Pi[i]**(1-alpha))
    
    return 1/(alpha-1)*math.log(sum1*sum2, 2)