#!/usr/bin/python3
# from distutils.core import setup
import ast
from setuptools import setup

try:
    from pathlib import Path
except ImportError:
    from pathlib2 import Path

def extract_value(v):
    if isinstance(v, ast.Str):
        return v.s
    elif isinstance(v, ast.Num):
        return v.n
    elif isinstance(v, ast.Call):
        for a in v.args:
            r = extract_value(a)
            if r is not None:
                return r

def extract_vars_from_python_AST(a):
    res = {}
    for e in a.body:
        if isinstance(e, ast.Assign) and len(e.targets) == 1:
            n = e.targets[0]
            if isinstance(n, ast.Name):
                res[n.id] = extract_value(e.value)
    return res

def extract_vars_from_python_source(p):
    with p.open("rt", encoding="utf-8") as f:
        t = f.read()
    return extract_vars_from_python_AST(ast.parse(t))

if __name__ == "__main__":
    thisDir = Path(__file__).parent.absolute()
    authorInfo = extract_vars_from_python_source(Path(thisDir / "pgpy" / "_author.py"))
    setup(
        version      = authorInfo["__version__"],
        author       = authorInfo["__author__"],
        license      = authorInfo["__license__"],
        download_url = "https://github.com/SecurityInnovation/PGPy/archive/{pgpy_ver}.tar.gz".format(pgpy_ver=authorInfo["__version__"]),
    )
