""" decorators.py
"""
import contextlib
import functools
import warnings

from singledispatch import singledispatch

from .errors import PGPError


def classproperty(fget):
    class ClassProperty(object):
        def __init__(self, fget):
            self.fget = fget
            self.__doc__ = fget.__doc__

        def __get__(self, cls, owner):
            return self.fget(owner)

        def __set__(self, obj, value):  # pragma: no cover
            raise AttributeError("Read-only attribute")

        def __delete__(self, obj):  # pragma: no cover
            raise AttributeError("Read-only attribute")

    return ClassProperty(fget)


def sdmethod(meth):
    sd = singledispatch(meth)

    def wrapper(obj, *args, **kwargs):
        return sd.dispatch(args[0].__class__)(obj, *args, **kwargs)

    wrapper.register = sd.register
    wrapper.dispatch = sd.dispatch
    wrapper.registry = sd.registry
    wrapper._clear_cache = sd._clear_cache
    functools.update_wrapper(wrapper, meth)
    return wrapper


def sdproperty(fget):
    def defset(obj, val):  # pragma: no cover
        raise TypeError(str(val.__class__))

    class SDProperty(property):
        def register(self, cls=None, fset=None):
            return self.fset.register(cls, fset)

        def setter(self, fset):
            self.register(object, fset)
            return type(self)(self.fget, self.fset, self.fdel, self.__doc__)

    return SDProperty(fget, sdmethod(defset))


class KeyAction(object):
    def __init__(self, *usage, **conditions):
        super(KeyAction, self).__init__()
        self.flags = set(usage)
        self.conditions = conditions

    @contextlib.contextmanager
    def usage(self, key):
        def _preiter(first, iterable):
            yield first
            for item in iterable:
                yield item

        em = {}
        em['keyid'] = key.fingerprint.keyid
        em['flags'] = ', '.join(flag.name for flag in self.flags)

        if len(self.flags):
            for _key in _preiter(key, key.subkeys.values()):
                if self.flags & _key.usageflags:
                    break

            else:  # pragma: no cover
                raise PGPError("Key {keyid:s} does not have the required usage flag {flags:s}".format(**em))

        else:
            _key = key

        if _key is not key:
            em['subkeyid'] = _key.fingerprint.keyid
            warnings.warn("Key {keyid:s} does not have the required usage flag {flags:s}; using subkey {subkeyid:s}"
                          "".format(**em), stacklevel=4)

        yield _key

    def check_attributes(self, key):
        for attr, expected in self.conditions.items():
            if getattr(key, attr) != expected:
                raise PGPError("Expected: {attr:s} == {eval:s}. Got: {got:s}"
                               "".format(attr=attr, eval=str(expected), got=str(getattr(key, attr))))

    def __call__(self, action):
        @functools.wraps(action)
        def _action(key, *args, **kwargs):
            # ignore_usage = kwargs.pop('ignore_usage', False)
            # if ignore_usage:
            #     self.check_attributes(key)
            #
            #     # do the thing
            #     return action(key, *args, **kwargs)

            with self.usage(key) as _key:
                self.check_attributes(key)

                # do the thing
                return action(_key, *args, **kwargs)

        return _action
