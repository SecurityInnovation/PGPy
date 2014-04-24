""" reg.py

regex helpers
"""

SIGNATURE_MAGIC = r'^-----BEGIN PGP SIGNATURE-----'

ASCII_ARMOR_BLOCK_REG = \
    r'^-----BEGIN PGP ([A-Z ]*)-----$\n'\
    r'(.*)\n\n'\
    r'(.*)'\
    r'^(=.{4})\n'\
    r'^-----END PGP \1-----$\n'

ASCII_ARMOR_BLOCK_FORMAT = \
    "-----BEGIN PGP {block_type}-----\n"\
    "{headers}\n"\
    "{packet}\n"\
    "={crc}\n"\
    "-----END PGP {block_type}-----\n"
