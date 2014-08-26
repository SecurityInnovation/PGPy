""" util.py

utility functions for PGPY
"""


# borrowed from the development version of cryptography
# https://github.com/pyca/cryptography/blob/master/cryptography/hazmat/primitives/asymmetric/rsa.py
def modinv(e, m):
    """
    Modular Multiplicative Inverse. Returns x such that: (x * e) % m == 1
    """
    x1, y1, x2, y2 = 1, 0, 0, 1
    a, b = e, m
    while b > 0:
        q, r = divmod(a, b)
        xn, yn = x1 - q * x2, y1 - q * y2
        a, b, x1, y1, x2, y2 = b, r, x2, y2, xn, yn
    return x1 % m
