import os
from collections import namedtuple

from cffi import FFI

here = os.path.dirname(os.path.abspath(__file__))

Source = namedtuple('Source', ('h', 'include'))


def _mk_ffi(sources, name='_libsecp256k1', **kwargs):
    _ffi = FFI()
    code = []

    for source in sources:
        with open(os.path.join(here, source.h), 'rt') as h:
            _ffi.cdef(h.read())
        code.append(source.include)

    code.append('#define PY_USE_BUNDLED')
    _ffi.set_source(name, '\n'.join(code), **kwargs)

    return _ffi


modules = [
    Source('secp256k1.h', '#include <secp256k1.h>'),
    Source('util.h', '#include <util.h>'),
    Source('scalar.h', '#include <scalar.h>'),
    Source('ecmult.h', '#include <ecmult.h>'),
    Source('scratch.h', '#include <scratch.h>'),
    Source('group.h', '#include <group.h>'),
    Source('field.h', '#include <field.h>'),
    Source('field_5x52.h', '#include <field_5x52.h>'),
    Source('ecmult_gen.h', '#include <ecmult_gen.h>'),
    Source('secp256k1_ecdh.h', '#include <secp256k1_ecdh.h>'),
    Source('secp256k1_recovery.h', '#include <secp256k1_recovery.h>'),
    Source('secp256k1_extrakeys.h', '#include <secp256k1_extrakeys.h>'),
    Source('secp256k1_schnorrsig.h', '#include <secp256k1_schnorrsig.h>'),
    Source('secp256k1_frost.h', '#include <secp256k1_frost.h>'),
]

ffi = _mk_ffi(modules, libraries=['secp256k1'])
