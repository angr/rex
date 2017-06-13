from distutils.core import setup
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


setup(
      name='rex',
      version='0.02',
      packages=['rex', 'rex.exploit', 'rex.exploit.cgc', 'rex.exploit.cgc.type1', 'rex.exploit.cgc.type2', 'rex.exploit.cgc.c_templates', 'rex.exploit.techniques', 'rex.exploit.shellcodes'],
      install_requires=[
            'angr',
            'povsim',
            'tracer',
            'angrop',
            'compilerex',
      ],
)
