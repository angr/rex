from distutils.core import setup
import subprocess

import pip
r = pip.req.RequirementSet(pip.locations.build_prefix, pip.locations.src_prefix, download_dir=None)
r.add_requirement(pip.req.InstallRequirement.from_line('git+ssh://git@git.seclab.cs.ucsb.edu:/angr/angrop.git#egg=angrop'))
r.add_requirement(pip.req.InstallRequirement.from_line('git+ssh://git@git.seclab.cs.ucsb.edu:/cgc/tracer.git#egg=tracer'))
r.prepare_files(pip.index.PackageFinder([], None))
r.install([], [])

setup(
      name='rex',
      version='0.01',
      packages=['rex', 'rex.exploit', 'rex.exploit.cgc', 'rex.exploit.cgc.payload', 'rex.exploit.techniques', 'rex.exploit.shellcodes'],
      install_requires=[
            'angr',
            'simuvex',
            'tracer',
            'angrop',
      ],
)
