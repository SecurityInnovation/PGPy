""" fileloader.py

File-based metaclass to reduce duplicate code.
"""
import os
import os.path
import requests

try:
    e = FileNotFoundError
except NameError:
    e = IOError


class FileLoader(object):
    @staticmethod
    def is_path(ppath):
        if bytes is not str and type(ppath) is bytes:
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
                self.path = lfile.name

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
            elif os.path.exists(lfile):
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
        elif type(lfile) in [str, bytes]:
            self.bytes = lfile.encode() if type(lfile) is str else lfile

        # some other thing
        else:
            raise TypeError(type(lfile) + "Not expected")  # pragma: no cover

        # try to kick off the parser
        # this only works on properly implemented children of this type
        if self.bytes != bytes():
            self.parse()

    def __bytes__(self):
        return self.bytes  # pragma: no cover

    def parse(self):
        pass

    def write(self):
        if self.path is None or (not os.path.exists(self.path) and not os.path.exists(os.path.dirname(self.path))):
            raise e("Invalid path: {path}".format(path=self.path))  # pragma: no cover

        with open(self.path, 'w' if self.is_ascii else 'wb') as fp:
            fp.write(str(self) if self.is_ascii else self.bytes)