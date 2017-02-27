""" check the export list to ensure only the public API is exported by pgpy.__init__
"""
import pytest

import importlib
import inspect


modules = ['pgpy.constants',
           'pgpy.decorators',
           'pgpy.errors',
           'pgpy.pgp',
           'pgpy.symenc',
           'pgpy.types',
           'pgpy.packet.fields',
           'pgpy.packet.packets',
           'pgpy.packet.types',
           'pgpy.packet.subpackets.signature',
           'pgpy.packet.subpackets.types',
           'pgpy.packet.subpackets.userattribute']


def get_module_objs(module):
    # return a set of strings that represent the names of objects defined in that module
    return { n for n, o in inspect.getmembers(module, lambda m: inspect.getmodule(m) is module) } | ({'FlagEnum',} if module is importlib.import_module('pgpy.types') else set())  # dirty workaround until six fixes metaclass stuff to support EnumMeta in Python >= 3.6


def get_module_all(module):
    return set(getattr(module, '__all__', set()))


def test_pgpy_all():
    import pgpy
    # just check that everything in pgpy.__all__ is actually there
    assert set(pgpy.__all__) <= { n for n, _ in inspect.getmembers(pgpy) }


@pytest.mark.parametrize('modname', modules)
def test_exports(modname):
    module = importlib.import_module(modname)

    assert get_module_all(module) == get_module_objs(module)
