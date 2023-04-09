import math
'''
    Calculates the generalized entropy of a probability distribution
    Input:  
            alpha:      int, the alpha
            Pi:         list of floats, probabilities
    Output: 
            entropy:    float, Generalized entropy of Pi

'''
def generalizedEntropy(alpha, Pi):
    sumProb = 0
    for pi in Pi:
        sumProb += pi**alpha

    return 1/(1-alpha)*math.log(sumProb, 2)