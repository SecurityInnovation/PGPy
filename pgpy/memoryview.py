""" util.py
"""
import six

__all__ = ('memoryview', )

memoryview = memoryview

if six.PY2:
    # because Python2's memoryview can't be released directly, nor can it be used as a context manager
    # this wrapper object should hopefully make the behavior more uniform to python 3's
    import __builtin__
    import functools

    # this decorator will raise a ValueError if the wrapped memoryview object has been "released"
    def notreleased(meth):
        @functools.wraps(meth)
        def _inner(self, *args, **kwargs):
            if self._mem is None:
                raise ValueError("operation forbidden on released memoryview object")
            return meth(self, *args, **kwargs)

        return _inner

    class memoryview(object):  # flake8: noqa
        @property
        @notreleased
        def obj(self):
            """The underlying object of the memoryview."""
            return self._obj

        @property
        @notreleased
        def nbytes(self):
            # nbytes == product(shape) * itemsize == len(m.tobytes())
            nb = 1
            for dim in self.shape:
                nb *= dim
            return nb * self.itemsize

        # TODO: c_contiguous -> (self.ndim == 0 or ???)
        # TODO: f_contiguous -> (self.ndim == 0 or ???)
        # TODO: contiguous -> return self.c_contiguous or self.f_contiguous

        def __new__(cls, obj, parent=None):
            memview = object.__new__(cls)
            memview._obj = obj if parent is None else parent.obj
            return memview

        def __init__(self, obj):
            if not hasattr(self, '_mem'):
                if not isinstance(obj, __builtin__.memoryview):
                    obj = __builtin__.memoryview(obj)
                self._mem = obj

        def __dir__(self):
            # so dir(...) looks like a memoryview object, and also
            # contains our additional methods and properties, but not our instance members
            return sorted(set(self.__class__.__dict__) | set(dir(self._mem)))

        @notreleased
        def __getitem__(self, item):
            # if this is a slice, it'll return another real memoryview object
            # we'll need to wrap that subview in another memoryview wrapper
            if isinstance(item, slice):
                return memoryview(self._mem.__getitem__(item))

            return self._mem.__getitem__(item)

        @notreleased
        def __setitem__(self, key, value):
            self._mem.__setitem__(key, value)

        @notreleased
        def __delitem__(self, key):
            raise TypeError("cannot delete memory")

        def __getattribute__(self, item):
            try:
                return object.__getattribute__(self, item)

            except AttributeError:
                if object.__getattribute__(self, '_mem') is None:
                    raise ValueError("operation forbidden on released memoryview object")

                return object.__getattribute__(self, '_mem').__getattribute__(item)

        def __setattr__(self, key, value):
            if key not in self.__dict__ and hasattr(__builtin__.memoryview, key):
                # there are no writable attributes on memoryview objects
                # changing indexed values is handled by __setitem__
                raise AttributeError("attribute '{}' of 'memoryview' objects is not writable".format(key))

            else:
                object.__setattr__(self, key, value)

        @notreleased
        def __len__(self):
            return len(self._mem)

        def __eq__(self, other):
            if isinstance(other, memoryview):
                return self._mem == other._mem

            return self._mem == other

        @notreleased
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.release()

        def __repr__(self):
            return '<{}memory at 0x{:02X}>'.format('' if self._mem else 'released ', id(self))

        def release(self):
            """Release the underlying buffer exposed by the memoryview object"""
            # this should effectively do the same job as memoryview.release() in Python 3
            self._mem = None
            self._obj = None

        @notreleased
        def hex(self):
            """Return the data in the buffer as a string of hexadecimal numbers."""
            return ''.join(('{:02X}'.format(ord(c)) for c in self._mem))

        # TODO: cast
