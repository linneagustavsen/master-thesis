from scipy.fft import rfft,irfft
import numpy as np

def fft_denoiser(y, n_components):
    n = len(y)
    yf = rfft(y)
    psd = yf * np.conj(yf) / n
    ind = np.argpartition(psd, -n_components)[-n_components:]

    mask_array = np.zeros(len(yf), dtype=int)
    mask_array[ind] = 1
    yf_clean = yf*mask_array

    clean_data = irfft(yf_clean)
    return clean_data