import mmap

try:
    from pathlib import Path
except ImportError:
    from pathlib2 import Path

class MMap:
    __slots__ = ("path", "f", "m")
    def __init__(self, path):
        path = Path(path)
        self.path = path
        self.f = None
        self.m = None
    
    def __enter__(self):
        self.f = self.path.open("rb")
        self.m = mmap.mmap(self.f.fileno(), 0, prot=mmap.PROT_READ)
        return self.m
    
    def __exit__(self, *args, **kwargs):
        self.m.close()
        self.f.close()
