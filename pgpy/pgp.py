""" pgp.py

"""

ASCII_ARMOR_BLOCK_REG = \
    r'^-----BEGIN %BLOCK_TYPE%-----$\n'\
    r'(.*)\n\n'\
    r'(.*)'\
    r'^(=.{4})\n'\
    r'^-----END %BLOCK_TYPE%-----$\n'

ASCII_ARMOR_BLOCK_FORMAT = \
    "-----BEGIN {block_type}-----\n"\
    "{headers}\n"\
    "{packet}\n"\
    "={crc}\n"\
    "-----END {block_type}-----\n"

class PGPError(Exception):
    pass