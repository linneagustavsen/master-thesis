'''

    The input has to be a list of probabilities from the distribution of this field.

'''
import math

def generalizedEntropy(alpha, Pi):
    sumProb = 0
    for pi in Pi:
        sumProb += pi**alpha

    return 1/(1-alpha)*math.log(sumProb, 2)