"""
Module to make script generation customizable
"""
import string

import jinja2


env = jinja2.Environment(
    loader=jinja2.PackageLoader('rex', 'scripter/templates'),
    trim_blocks=True)

# might be useful for python string to c string translation, for c expoit generation
def cstring(b):
    assert type(b) is bytes
    printable = set(ord(e) for e in
                    (string.ascii_letters + string.digits + string.punctuation + ' ')
                    if e not in '\\"')
    result = ''.join(chr(i) if i in printable else ('\\' + oct(i)[2:].rjust(3, '0'))
                     for i in b)
    return '"' + result + '"'

env.filters['cstring'] = cstring


class Scripter:
    """
    A scripter object that translates rex actions into standalone exploit scripts
    """

    def __init__(self, crash, stype='py'):
        self._template = env.get_template(stype+ '.j2')
        self.crash = crash
        self._stype = stype

    def script(self, filename=None):
        """
        write the whole script
        """
        result = self._template.render(actions=self.crash.actions)
        if filename:
            with open(filename, 'w') as f:
                f.write(result)
        return result
