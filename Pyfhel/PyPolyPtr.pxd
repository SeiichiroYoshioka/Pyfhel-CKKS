# distutils: language = c++
#cython: language_level=3, boundscheck=False

# -------------------------------- CIMPORTS -----------------------------------
# import both numpy and the Cython declarations for numpy
cimport numpy as np

# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.vector cimport vector
from libcpp cimport bool
from libcpp.complex cimport complex as cpp_complex
from numpy cimport int64_t, uint64_t

from Pyfhel.Pyfhel cimport *

# Import our own wrapper for iostream classes, used for I/O ops
from Pyfhel.iostream cimport istream, ostream, ifstream, ofstream, ostringstream, stringstream, binary

# Encoding types: 0-UNDEFINED, 1-INTEGER, 2-FRACTIONAL, 3-BATCH
from Pyfhel.util cimport ENCODING_T

# ---------------------------- CYTHON DECLARATION ------------------------------
cdef class PyPolyPtr:
    cdef uint64_t * poly_ptr  # The C++ methods are accessed via a pointer
    cpdef void allocate_zero_poly(self, uint64_t n, uint64_t coeff_mod_count) except +