""" types.py
"""
import os

import requests

# Python 2.7 hacks
try:  # pragma: no cover
    e = FileNotFoundError
except NameError:  # pragma: no cover
    e = IOError
try:  # pragma: no cover
    basestring
except NameError:  # pragma: no cover
    basestring = (str, bytes)


class FileLoader(object):
    @staticmethod
    def is_path(ppath):
        if (bytes is not str and type(ppath) is bytes) or type(ppath) is bytearray:
            return False

        # this should be adequate most of the time
        # we'll detect all unprintable and extended ASCII characters as 'bad' - their presence will denote 'not a path'
        badchars = [ chr(c) for c in range(0, 32) ]
        badchars += [ chr(c) for c in range(128, 256) ]

        # Windows also specifies some reserved characters
        if os.name == "nt":
            badchars += ['<', '>', ':', '"', '/', '\\', '|', '?', '*']  # pragma: no cover

        if any(c in ppath for c in badchars):
            return False  # pragma: no cover

        return True

    @property
    def is_ascii(self):
        try:
            self.bytes.decode()
            return True

        except UnicodeDecodeError:
            return False

    def __init__(self, lfile):
        self.bytes = bytes()
        self.path = None

        # None means we're creating a new file, probably in-memory
        if lfile is None:
            pass

        # we have been passed a file-like object
        elif hasattr(lfile, "read"):
            self.bytes = bytes(lfile.read())

            # try to extract the path, too
            if hasattr(lfile, "name") and os.path.exists(os.path.realpath(lfile.name)):
                self.path = os.path.realpath(lfile.name)

        # str without NUL bytes means this is likely a file path or URL
        # because in 2.x, bytes is just an alias of str
        elif FileLoader.is_path(lfile):
            # is this a URL?
            if "://" in lfile and '\n' not in lfile:
                r = requests.get(lfile, verify=True)

                if not r.ok:
                    raise e(lfile)  # pragma: no cover

                self.bytes = r.content

            # this may be a file path, then
            # does the path already exist?
            elif os.path.exists(lfile) and os.path.isfile(lfile):
                self.path = os.path.realpath(lfile)

                with open(lfile, 'rb') as lf:
                    self.bytes = bytes(lf.read())

            # if the file does not exist, does the directory pointed to exist?
            elif os.path.isdir(os.path.dirname(lfile)):
                self.path = os.path.realpath(lfile)

            # if the file does not exist and its directory path does not exist,
            # you're gonna have a bad time
            else:
                raise e(lfile)

        # we have been passed the contents of a file that were read elsewhere
        elif isinstance(lfile, basestring):
            try:
                self.bytes = bytearray(lfile, 'latin-1') if hasattr(lfile, 'encode') else bytearray(lfile)

            # this is because Python 2.7 is stupid about unicode
            # if a str contains bytes that cannot be expressed in ASCII, it must be 'decoded' to unicode first
            # and then encoded to 'latin-1'
            except UnicodeDecodeError:
                self.bytes = bytearray(lfile.decode('latin-1'), 'latin-1')

        elif isinstance(lfile, bytearray):
            self.bytes = lfile

        # some other thing
        else:
            raise TypeError(str(type(lfile)) + " Not expected")  # pragma: no cover

        # try to kick off the parser
        # this only works on properly implemented children of this type
        if self.bytes != bytes():
            self.parse()

    def __bytes__(self):
        return self.bytes  # pragma: no cover

    def parse(self):
        pass

    def write(self):
        """
        Writes the loaded contents to disk, at the path specified in :py:attr:`path`

        :raises:
            :py:exc:`FileNotFoundError` (or :py:exc:`IOError` on Python 2.x) if :py:attr:`.path` is invalid or None
        """
        if self.path is None or (not os.path.exists(self.path) and not os.path.exists(os.path.dirname(self.path))):
            raise e("Invalid path: {path}".format(path=self.path))  # pragma: no cover

        with open(self.path, 'w' if self.is_ascii else 'wb') as fp:
            fp.write(str(self) if self.is_ascii else self.bytes)


class SignatureVerification(object):
    """
    Returned by :py:meth:`pgpy.PGPKeyring.verify`

    Can be compared directly as a boolean to determine whether or not the specified signature verified.
    """
    def __init__(self):
        self._verified = False

        self.signature = None
        """
        The :py:class:`~pgpy.pgp.PGPSignature` that was used in the verification that returned this
        """
        self.key = None
        """
        The key (if available) that was used to verify the signature
        """
        self.subject = None
        """
        The subject of the verification
        """

    # Python 2
    def __nonzero__(self):
        return self._verified  # pragma: no cover

    # Python 3
    def __bool__(self):
        return self._verified  # pragma: no cover

    def __repr__(self):  # pragma: no cover
        return "SignatureVerification({key}, {verified})".format(verified=str(bool(self)), key=self.key.keyid)
