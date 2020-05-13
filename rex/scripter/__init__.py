"""
Module to make script generation customizable
"""
import string

import jinja2


env = jinja2.Environment(
    loader=jinja2.PackageLoader('rex', 'scripter/templates'),
    trim_blocks=True)

def cstring(b):
    assert type(b) is bytes
    printable = set(ord(e) for e in
                    (string.ascii_letters + string.digits + string.punctuation + ' ')
                    if e not in '\\"')
    result = ''.join(chr(i) if i in printable else ('\\' + oct(i)[2:].rjust(3, '0'))
                     for i in b)
    return '"' + result + '"'

env.filters['cstring'] = cstring


class ScripterVariableProxy:
    def __init__(self, scripter, name, value=None, type_=None):
        self.scripter = scripter
        self.name = name
        self.value = value
        self.type_ = type_

    def __str__(self):
        return self.name

    def __len__(self):
        return len(self.value)


class ScripterFunctionProxy:
    def __init__(self, scripter, name):
        self.scripter = scripter
        self.name = name

    def __call__(self, *args):
        function_result = ScripterVariableProxy(self.scripter, None)
        self.scripter.add_action(ScripterAction(function_result, self, *args))
        return function_result

    def __str__(self):
        return self.name


class ScripterAction:
    def __init__(self, function_result, function, *args):
        self.function_result = function_result
        self.function = function
        self.args = []
        for arg in args:
            if type(arg) is str:
                arg = arg.encode('latin')
            if type(arg) is ScripterVariableProxy:
                if arg.name is None:
                    raise ValueError("Cannot reference unbound variable")
                self.args.append(arg)
            elif type(arg) in [bytes, int, float]:
                self.args.append(arg)
            else:
                raise ValueError(f"Unsupported arg type: {type(arg)}")


class Scripter:
    """
    A scripter object is the abstraction of exploit generation.
    It is used to generate standalone exploits according to user provided specifications
    """
    __slots__ = ['_template', 'constants', 'variables', 'actions']

    def __init__(self, template='python', predefined_constants=None):
        if predefined_constants is None:
            predefined_constants = []
        self._template = env.get_template(template + '.j2')
        self.constants = {c: ScripterVariableProxy(self, c) for c in predefined_constants}
        self.variables = {}
        self.actions = []

    def add_action(self, action):
        self.actions.append(action)

    def __setattr__(self, name, value):
        if name in self.__slots__:
            super().__setattr__(name, value)
            return

        if name in self.constants or name in self.variables:
            raise ValueError(f"Name `{name}` already used")

        if isinstance(value, tuple):
            type_, value = value
        else:
            type_ = None

        if isinstance(value, ScripterVariableProxy):
            if value.name is not None:
                raise ValueError("Variable already bound")
            value.name = name
            self.variables[name] = value
            if type_:
                value.type_ = type_
            return

        if type(value) is str:
            value = value.encode('latin')
        if type(value) in [bytes, int, float]:
            self.constants[name] = ScripterVariableProxy(self, name, value)
        else:
            raise ValueError("Constant value must be of type `bytes`, `int`, or `float`")

    def __getattr__(self, name):
        if name in self.constants:
            return self.constants[name]
        elif name in self.variables:
            return self.variables[name]
        else:
            return ScripterFunctionProxy(self, name)

    def script(self, filename=None):
        """
        write the whole script
        """
        result = self._template.render(constants=self.constants, actions=self.actions)
        if filename:
            with open(filename, 'w') as f:
                f.write(result)
        return result
