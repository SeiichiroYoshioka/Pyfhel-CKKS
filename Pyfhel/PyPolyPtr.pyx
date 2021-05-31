# distutils: language = c++
#cython: language_level=3, boundscheck=False

#   --------------------------------------------------------------------
#   Pyfhel.pyx
#   Author: Alberto Ibarrondo
#   Date: 17/07/2018
#   --------------------------------------------------------------------
#   License: GNU GPL v3
#
#   Pyfhel is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   Pyfhel is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#   --------------------------------------------------------------------

# -------------------------------- IMPORTS ------------------------------------
# Both numpy and the Cython declarations for numpy
import numpy as np

np.import_array()

# Type checking for only numeric values
from numbers import Number

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref
from libcpp.complex cimport complex as cpp_complex
# Importing it for the fused types
cimport cython

# Encoding types: 0-UNDEFINED, 1-INTEGER, 2-FRACTIONAL, 3-BATCH
from Pyfhel.util import ENCODING_t
from .Pyfhel import Pyfhel

# Define Plaintext types
FLOAT_T = (float, np.float16, np.float32, np.float64)
INT_T = (int, np.int16, np.int32, np.int64, np.int_, np.intc)

# Import utility functions
include "util/utils.pxi"

# ------------------------- PYTHON IMPLEMENTATION -----------------------------
cdef class PyPolyPtr:
    """Simple Wrapper around raw pointers to polynomials
    """
    def __cinit__(self, Pyfhel pyfhel = None):
        self.poly_ptr = NULL
        if (pyfhel):
            self._pyfhel = pyfhel

    def __init__(self, Pyfhel pyfhel=None, ):
        """__init__()

        Initializes an empty  PyPolyPtr (nullptr)
        """
        self._pyfhel = pyfhel

    def __dealloc__(self):
        if self.poly_ptr != NULL:
            pass  #memory is handled by a pool, not by us

    def __iter__(self):
        return self

    def __repr__(self):
        """A printable string with all the information about the PyPolyPtr object

        """
        return "<PyPolyPtr - no time to implement fancy printing stuff>"

    def __reduce__(self):
        """__reduce__(self)

        Required for pickling purposes. Returns a tuple with:
            - A callable object that will be called to create the initial version of the object.
            - A tuple of arguments for the callable object.
        """
        return PyPolyPtr, (None)

    cpdef void allocate_zero_poly(self, uint64_t n, uint64_t coeff_mod_count) except +:
        self._pyfhel.afseal.allocate_zero_poly(n, coeff_mod_count, <uint64_t>&self.poly_ptr[0])
