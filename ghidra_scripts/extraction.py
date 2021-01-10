__all__ = ['extract']

from array import array
from functools import partial
from collections import namedtuple

from ghidra.program.model.pcode import PcodeOpAST, VarnodeAST, SequenceNumber
from ghidra.program.model.address import Address, AddressSpace

def extract(obj):
    if obj == None: return None

    typ = type(obj)
    for cls in (typ,) + typ.__bases__:
        if cls in extracts:
            props, specifier = extracts[cls]
            break
    else:
        raise ValueError('Illegal type: ' + str(typ))

    if '_all' in specifier:
        return specifier['_all'](obj)

    ret = {}
    for prop in props:
        if prop.startswith('get-'):
            prop = prop[4:]
            val = getattr(obj, 'get' + prop.capitalize())()
        else:
            val = getattr(obj, prop)

        if prop in specifier:
            val = specifier[prop](val)
        else:
            val = extract(val)
        ret[prop] = val
    return ret

_retself = ([], {'_all': lambda data: data})
extracts = {
    int: _retself,
    long: _retself,
    str: _retself,
    unicode: _retself,
    dict: ([], {'_all': lambda data: {key: extract(value)
        for (key, value) in data.items()}}),
    list: ([], {'_all': lambda data: [extract(value) for value in data]}),
    array: ([], {'_all': lambda data: [extract(value) for value in data]}),
    VarnodeAST: ([
        'get-address', # Address
        'addrTied', # Bool
        'def', # Maybe SequenceNumber
        'size', # Int
        'free', # Bool
        'hash', # Bool
        'input', # Bool
        'persistant', # Bool
        'register', # Bool
        'unaffected', # Bool
        'unique', # Bool
        'uniqueId'], # Int
        {'def': lambda val: None if val == None else extract(val.seqnum) }),
    PcodeOpAST: ([
        'dead', # Bool
        'inputs', # [VarnodeAST]
        'mnemonic', # String
        'seqnum', # SequenceNumber
        'output', # VarnodeAST
        ], {}),
    SequenceNumber: ([
        'order', # Int
        'time', # Int
        'target', # Address
        ], {}),
    Address: ([
        'addressSpace', # Int
        'offset', # Int
        ], {'addressSpace': lambda val: val.name}),
    AddressSpace: ([
        'baseSpaceID', # Int
        'name', # String
        ], {}),
}

