import math

'''
    Calculates the information distance between two probability distributions
    Input:  alpha:  int, the alpha
            Pi:     list of floats, probabilities of a distribution
            Qi:     list of floats, probabilities of a distribution
            n:      int, the length of the distribution lists
    Output:         float, Information distance

'''
def informationDistance(alpha, Pi, Qi, n):
    sum1 = 0
    sum2 = 0
    for i in range(n):
        sum1 += (Pi[i]**alpha)*(Qi[i]**(1-alpha))
        sum2 += (Qi[i]**alpha)*(Pi[i]**(1-alpha))
    
    return 1/(1-alpha)*math.log(sum1*sum2, 2)