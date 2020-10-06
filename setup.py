import ast
import os.path

from setuptools import setup


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


def extract_vars_from_python_ast(a):
    res = {}
    for e in a.body:
        if isinstance(e, ast.Assign) and len(e.targets) == 1:
            n = e.targets[0]
            if isinstance(n, ast.Name):
                res[n.id] = extract_value(e.value)
    return res


def extract_vars_from_python_source(p):
    with open(p) as f:
        t = f.read()
    return extract_vars_from_python_ast(ast.parse(t))


this_dir = os.path.dirname(os.path.abspath(__file__))
author_info = extract_vars_from_python_source(os.path.join(this_dir, "pgpy", "_author.py"))
setup(
    version=author_info["__version__"],
    author=author_info["__author__"],
    license=author_info["__license__"],
)
