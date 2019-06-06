import os
import subprocess

#TRACER_URL = 'git+ssh://git@git.seclab.cs.ucsb.edu:/cgc/tracer.git#egg=tracer'
#ANGROP_URL = 'git+ssh://git@git.seclab.cs.ucsb.edu:/angr/angrop.git#egg=angrop'
#
## this is really gross, but you do what you gotta do
#if subprocess.call(['pip', 'install', TRACER_URL]) != 0:
#   raise LibError("Unable to install tracer")
#
#if subprocess.call(['pip', 'install', ANGROP_URL]) != 0:
#   raise LibError("Unable to install angrop")

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
            'povsim',
            'tracer',
            'angrop',
            'compilerex',
            'archr',
      ],
      dependency_links=[
          'git+ssh://git@github.com/mechaphish/compilerex#egg=compilerex',
          'git+ssh://git@github.com/mechaphish/povsim#egg=povsim',
          'git+ssh://git@github.com/angr/archr#egg=archr',
          'git+ssh://git@github.com/angr/tracer#egg=tracer',
      ],
)
