'''

    Input: list of probabilities and the alpha
    Output: Generalized entropy

'''
import math

def generalizedEntropy(alpha, Pi):
    sumProb = 0
    for pi in Pi:
        sumProb += pi**alpha

    return 1/(1-alpha)*math.log(sumProb, 2)