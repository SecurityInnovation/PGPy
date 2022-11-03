""" test copying PGP objects
"""
from __future__ import print_function
import pytest

import copy
import glob
import inspect
import os.path

import pgpy

from pgpy import PGPSignature, PGPUID, PGPMessage, PGPKey


_keys = glob.glob('tests/testdata/keys/*.1.pub.asc') + glob.glob('tests/testdata/keys/*.1.sec.asc')
_msgs = [ 'tests/testdata/messages/message.{}.asc'.format(f) for f in ['signed', 'rsa.cast5.no-mdc', 'rsa.dsa.pass.aes']]


def sig():
    return PGPSignature.from_file('tests/testdata/blocks/rsasignature.asc')


def uid():
    return PGPUID.new('Abraham Lincoln', comment='Honest Abe', email='abraham.lincoln@whitehouse.gov')


def key(fn):
    key, _ = PGPKey.from_file(fn)
    return key


def walk_obj(obj, prefix=""):
    from enum import Enum

    for name, val in inspect.getmembers(obj):
        if hasattr(obj.__class__, name):
            continue

        yield '{}{}'.format(prefix, name), val

        if not isinstance(val, Enum):
            for n, v in walk_obj(val, prefix="{}{}.".format(prefix, name)):
                yield n, v


def check_id(obj):
    from datetime import datetime
    from enum import Enum

    # do some type checking to determine if we should check the identity of an object member
    # these types are singletons
    if isinstance(obj, (Enum, bool, type(None))):
        return False

    # these types are immutable
    if isinstance(obj, (str, datetime)):
        return False

    # integers are kind of a special case.
    #   ints that do not exceed sys.maxsize are singletons, and in either case are immutable
    #   this shouldn't apply to MPIs, though, which are subclasses of int
    if isinstance(obj, int) and not isinstance(obj, pgpy.packet.types.MPI):
        return False

    return True


def ksort(key):
    # return a tuple of key, key.count('.') so we get a descending alphabetical, ascending depth ordering
    return key, key.count('.')


objs = [sig(), uid(),] + [PGPMessage.from_file(m) for m in _msgs] + [key(f) for f in _keys]
cids = ['sig', 'uid',] + [os.path.basename(m) for m in _msgs] + [os.path.basename(f) for f in _keys]


@pytest.mark.parametrize('obj', objs, ids=cids)
def test_copy_obj(request, obj):
    obj2 = copy.copy(obj)

    objflat = {name: val for name, val in walk_obj(obj, '{}.'.format(request.node.callspec.id))}
    obj2flat = {name: val for name, val in walk_obj(obj2, '{}.'.format(request.node.callspec.id))}

    for k in sorted(objflat, key=ksort):
        print("checking attribute: {} ".format(k), end="")
        if isinstance(objflat[k], pgpy.types.SorteDeque):
            print("[SorteDeque] ", end="")
            assert len(objflat[k]) == len(obj2flat[k])

        if not isinstance(objflat[k], (pgpy.types.PGPObject, pgpy.types.SorteDeque)):
            print("[{} ]".format(type(objflat[k])), end="")
            assert objflat[k] == objflat[k], k

        # check identity, but only types that should definitely be copied
        if check_id(objflat[k]):
            print("[id] {}".format(type(objflat[k])))
            assert objflat[k] is not obj2flat[k], "{}: {}".format(type(objflat[k]), k)

        else:
            print()
