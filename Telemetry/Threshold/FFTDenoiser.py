from scipy.fft import rfft,irfft
import numpy as np

'''
    Input:  array of values 
            how many energy coefficients to keep
    Output: denoised array of values by using Fast Fourier Transform
'''

def fft_denoiser(y, n_components):
    n = len(y)
    #Do FFT on the data
    yf = rfft(y)
    #Calculate the power spectral density
    psd = yf * np.conj(yf) / n
    #Get the number of the highest energy coefficients that is specified
    ind = np.argpartition(psd, -n_components)[-n_components:]

    #Make a mask array
    mask_array = np.zeros(len(yf), dtype=int)
    mask_array[ind] = 1
    #Get the right frequencies by multiplying with the mask
    yf_clean = yf*mask_array

    #Do inverse FFT to get the denoised values
    clean_data = irfft(yf_clean)
    return clean_data