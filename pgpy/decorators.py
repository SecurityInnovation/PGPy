""" decorators.py
"""

import functools

from .errors import PGPError

class TypedProperty(property):
    """
    """
    def __init__(self, fget=None, fset=None, fdel=None, doc=None, **kwargs):
        for k in kwargs:
            setattr(self, k, kwargs[k])

        super(TypedProperty, self).__init__(fget, fset, fdel, doc)

    def __set__(self, obj, val):
        ##TODO: being able to detect subclasses would be cool
        if 'fset' + val.__class__.__name__ in self.__dict__:
            getattr(self, 'fset' + val.__class__.__name__)(obj, val)

        else:
            super(TypedProperty, self).__set__(obj, val)

    def __getattr__(self, item):
        def _typedsetter(ftypedsetter):
            """
            This is a catch-all method for TypedProperty
            So, when you decorate a class like so:
            class A(object):
                @TypedProperty
                def a(self):
                    return self._a
                @a.setter
                def a(self, val):
                    self._a = val
                @a.bytes
                def a(self, val):
                    self._a = int.from_bytes(val, 'big')

            @a.fsetbytes is set automagically and when val's type is 'bytes',
            that setter is called instead of the default one

            This should work with anything, because fset{x} is set by the setter, and selected by __class__.__name__
            """
            cur_setters = dict((k, v) for k, v in self.__dict__.items()) # if k[:4] == 'fset' and k != 'fset'
            if isinstance(ftypedsetter, TypedProperty):
                # ftypedsetter at this point is a TypedProperty
                # in this instance, something like this happened:
                # class A(object):
                #     @TypedProperty
                #     def x(self):
                #         return self._x
                #     @x.bytearray
                #     @x.bytes
                #     def x(self, val):
                #         self._x = int.from_bytes(val, 'big')
                #
                # so we need to replace ftypedsetter with the function already wrapped in the instance in ftypedsetter
                # it should be the only key in ftypedsetter.__dict__ that isn't in self.__dict__
                diff = dict(set(ftypedsetter.__dict__.items()) - set(self.__dict__.items()))
                if len(diff) > 0:
                    ftypedsetter = list(diff.values())[0]
                    cur_setters.update(diff.items())

            cur_setters['fset' + item] = ftypedsetter

            return type(self)(self.fget, self.fset, self.fdel, self.__doc__, **cur_setters)

        # this fixes some python 2.7/3.2 shenanigans
        if item == '__isabstractmethod__':
            raise AttributeError(item)

        if item in self.__dict__ or item in ['fset', 'fget', 'fdel', '__doc__']:
            return self.__dict__[item]

        if 'fset' + item in self.__dict__:
            return 'fset' + item in self.__dict__

        return _typedsetter


class Managed(object):
    def __init__(self, selection_required=False, pub_required=False, priv_required=False):
        self.required = selection_required
        self.pub_required = pub_required
        self.priv_required = priv_required

    def __call__(self, fn):
        @functools.wraps(fn)
        def decorated(iself, *args, **kwargs):
            if not iself.ctx:
                raise PGPError("Invalid usage - this method must be invoked from a context managed state!")

            if self.required:
                if iself.using is None:
                    raise PGPError("Must select a loaded key!")

                if iself.using not in iself._keys:
                    raise PGPError("Key {keyid} is not loaded!".format(keyid=iself.using))

            if self.pub_required and iself.using is not None and iself.selected.pubkey is None:
                raise PGPError("Public Key {keyid} is not loaded!".format(keyid=iself.using))

            if self.priv_required and iself.using is not None and iself.selected.privkey is None:
                raise PGPError("Private Key {keyid} is not loaded!".format(keyid=iself.using))

            return fn(iself, *args, **kwargs)

        return decorated


# just an alias; nothing to see here
managed = Managed
