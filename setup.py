from distutils.core import setup

setup(
      name='rex',
      version='0.01',
      packages=['rex', 'rex.exploit', 'rex.exploit.cgc', 'rex.exploit.cgc.payload', 'rex.exploit.techniques', 'rex.exploit.shellcodes'],
      install_requires=[
            'angr',
            'simuvex',
            'git+ssh://git@git.seclab.cs.ucsb.edu:/cgc/tracer.git#egg=tracer',
            'git+ssh://git@git.seclab.cs.ucsb.edu:/angr/angrop.git#egg=angrop',
      ],
)
