import os
import subprocess

try:
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    packages = [x.strip('./').replace('/', '.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

setup(
    name='rex',
    version='0.02',
    packages=packages,
    install_requires=[
        'angr',
        'archr',
        'angrop',
        'tracer @ git+https://github.com/angr/tracer',
        'povsim @ git+https://github.com/mechaphish/povsim',
        'compilerex @ git+https://github.com/mechaphish/compilerex',
    ],
)
