from distutils.core import setup

setup(
      name='rex',
      version='0.01',
      packages=['rex', 'rex.exploit', 'rex.exploit.cgc', 'rex.exploit.cgc.payload', 'rex.exploit.techniques', 'rex.exploit.shellcodes'],
      install_requires=[
            'angr',
            'simuvex',
            'tracer==0.1',
            'angrop==1.0',
      ],
      dependency_links=[
            'git+ssh://git@git.seclab.cs.ucsb.edu:/cgc/tracer.git#egg=tracer-0.1',
            'git+ssh://git@git.seclab.cs.ucsb.edu:/angr/angrop.git#egg=angrop-1.0',
      ],
)
