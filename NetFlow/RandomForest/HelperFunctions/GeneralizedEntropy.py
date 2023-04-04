import math
'''

    Input:  alpha:  int, the alpha
            Pi:     list of floats, probabilities
    Output: float, Generalized entropy of Pi

'''
def generalizedEntropy(alpha, Pi):
    sumProb = 0
    for pi in Pi:
        sumProb += pi**alpha

    return 1/(1-alpha)*math.log(sumProb, 2)