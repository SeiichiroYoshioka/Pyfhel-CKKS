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

# Define Plaintext types
FLOAT_T = (float, np.float16, np.float32, np.float64)
INT_T = (int, np.int16, np.int32, np.int64, np.int_, np.intc)

# Import utility functions
include "util/utils.pxi"

# ------------------------- PYTHON IMPLEMENTATION -----------------------------
cdef class Pyfhel:
    """Context class encapsulating most of the Homomorphic Encryption functionalities.

    Encrypted addition, multiplication, substraction, exponentiation of 
    integers/doubles. Implementation of homomorphic encryption using 
    SEAL/PALISADE/HELIB as backend. Pyfhel works with PyPtxt as  
    plaintext class and PyCtxt as cyphertext class.
    """
    def __cinit__(self,
                  context_params=None,
                  key_gen=False,
                  pub_key_file=None,
                  sec_key_file=None):
        self.afseal = new Afseal()

    def __init__(self,
                 context_params=None,
                 key_gen=False,
                 pub_key_file=None,
                 sec_key_file=None):
        """__init__(context_params=None, key_gen=False, pub_key_file=None, sec_key_file=None)

        Initializes an empty Pyfhel object, the base for all operations.
        
        To fill the Pyfhel object during initialization you can:
            - Provide a dictionary of context parameters to run Pyfhel.contextGen(**context_params). 
            - Set key_gen to True in order to generate a new public/secret key pair.
            - Provide a pub_key_file and/or sec_key_file to load existing keys from saved files.

        Attributes:
            context_params (dict, optional): dictionary of context parameters to run contextGen().
            key_gen (bool, optional): generate a new public/secret key pair
            pub_key_file (str, pathlib.Path, optional): Load public key from this file.
            sec_key_file (str, pathlib.Path, optional): Load public key from this file.
        """
        if context_params is not None:
            self.contextGen(**context_params)
        if key_gen:  # Overrides the key files
            self.keyGen()
        else:
            if pub_key_file is not None:
                self.restorepublicKey(pub_key_file)
            if sec_key_file is not None:
                self.restoresecretKey(sec_key_file)

    def __dealloc__(self):
        if self.afseal != NULL:
            del self.afseal

    def __iter__(self):
        return self

    def __repr__(self):
        """A printable string with all the information about the Pyfhel object
        
        Info:
            * at: hex ID, unique identifier and memory location.
            * pk: 'Y' if public key is present. '-' otherwise.
            * sk: 'Y' if secret key is present. '-' otherwise.
            * rtk: 'Y' if rotation keys are present. '-' otherwise.
            * rlk: 'Y' if relinarization keys are present. '-' otherwise.
            * contx: Context, with values of p, m, base, security,
                        # of int and frac digits and wether flagBatching is enabled.
        """
        return "<Pyfhel obj at {}, [pk:{}, sk:{}, rtk:{}, rlk:{}, contx({})]>".format(
            hex(id(self)),
            "-" if self.is_publicKey_empty() else "Y",
            "-" if self.is_secretKey_empty() else "Y",
            "-" if self.is_rotKey_empty() else "Y",
            "-" if self.is_relinKey_empty() else f"Y[{self.relinBitCount()}b]",
            "-" if self.is_context_empty() else \
                f"p={self.getp()}, m={self.getm()}, base={self.getbase()}, " \
                f"sec={self.getsec()}, dig={self.getintDigits()}i.{self.getfracDigits()}f, "
                f"batch={self.getflagBatch()}")

    def __reduce__(self):
        """__reduce__(self)

        Required for pickling purposes. Returns a tuple with:
            - A callable object that will be called to create the initial version of the object.
            - A tuple of arguments for the callable object.
        """
        context_params = {"p": self.p,
                          "m": self.m,
                          "flagBatching": self.flagBatch,
                          "base": self.base,
                          "sec": self.sec,
                          "intDigits": self.intDigits,
                          "fracDigits": self.fracDigits}
        return (Pyfhel, (context_params, False, None, None))

    @property
    def p(self):
        """Plaintext modulus. All operations are modulo p"""
        return self.getp()

    @property
    def m(self):
        """Polynomial coefficient modulus. (1*x^m+1). 
                
        Directly linked to the multiplication depth (see multDepth)."""
        return self.getm()

    @property
    def sec(self):
        """Security (bits)."""
        return self.getsec()

    @property
    def base(self):
        """Polynomial base."""
        return self.getbase()

    @property
    def intDigits(self):
        """Truncated positions for integer part in FRACTIONAL encoding"""
        return self.getintDigits()

    @property
    def fracDigits(self):
        """Truncated positions for decimal part in FRACTIONAL encoding"""
        return self.getfracDigits()

    @property
    def flagBatch(self):
        """Wether batching is enabled or not"""
        return self.getflagBatch()

    # =========================================================================
    # ============================ CRYPTOGRAPHY ===============================
    # =========================================================================

    cpdef contextGen(self, long n=16384, bool flagBatching=False,
                     long base=2, long sec=128, int intDigits=64,
                     int fracDigits = 32, vector[int] qs=vector[int](5, 30)) except +:
        """contextGen(int p, int m=2048, bool flagBatching=False, int base=2, int sec=128, int intDigits=64, int fracDigits = 32)
        
        Generates Homomorphic Encryption context based on parameters.
        
        Creates a HE context based in parameters, as well as integer,
        fractional and batch encoders. The HE context is required for any 
        other function (encryption/decryption,encoding/decoding, operations)
        
        Batch encoding is available if p is prime and p-1 is multiple of 2*m
        
        Some tips: 

        - m-> Higher allows more encrypted operations. In batch mode it
            is the number of integers per ciphertext.
        - base-> Affects size of plaintexts and ciphertexts, and FRACTIONAL
            encoding.
        - intDigits & fracDigits-> applicable with FRACTIONAL encoding.

        Args:
            p (int): Plaintext modulus. All operations are modulo p.
            m (int): Polynomial coefficient modulus. (Poly: 1*x^m+1). 
                directly linked to the multiplication depth (see multDepth).
            flagBatching (bool): Set to true to enable batching.
            base (int): Polynomial base. 
            sec (int): Security level equivalent in AES. 128 or 192.
            intDigits (int): truncated positions for integer part.
            fracDigits (int): truncated positions for fractional part.
                      
        Return:
            None
        """
        self.afseal.ContextGen(n, flagBatching, base,
                               sec, intDigits, fracDigits, qs)

    cpdef void keyGen(self) except +:
        """keyGen()
        
        Generates a pair of secret/Public Keys.
        
        Based on the current context, initializes a public/secret key pair.
        
        Args:
            None

        Return:
            None
        """
        self.afseal.KeyGen()

    # .............................. ENCYRPTION ...............................

    cpdef PyCtxt encrypt(self, PyPtxt ptxt, PyCtxt ctxt=None) except +:
        """encrypt(PyPtxt ptxt, PyCtxt ctxt=None)
        
        Encrypts an encoded PyPtxt plaintext into a PyCtxt ciphertext.
        
        Encrypts an encoded PyPtxt plaintext using the current secret
        key, based on the current context. Plaintext must be a PyPtxt.
        If provided a ciphertext, encrypts the plaintext inside it. 
        
        Args:
            ptxt (PyPtxt): plaintext to encrypt.
            ctxt (PyCtxt, optional): Optional destination ciphertext.  
            
        Return:
            PyCtxt: the ciphertext containing the encrypted plaintext
            
        Raise:
            TypeError: if the plaintext doesn't have a valid type.
        """
        if (ptxt._ptr_ptxt == NULL or ptxt is None):
            raise TypeError("<Pyfhel ERROR> PyPtxt Plaintext is empty")
        if ctxt is None:
            ctxt = PyCtxt()
        self.afseal.encrypt(deref(ptxt._ptr_ptxt), deref(ctxt._ptr_ctxt))
        ctxt._encoding = ptxt._encoding
        ctxt._pyfhel = self
        return ctxt

    # .............................. DECRYPTION ...............................

    cpdef PyPtxt decrypt(self, PyCtxt ctxt, PyPtxt ptxt=None) except +:
        """decrypt(PyCtxt ctxt, PyPtxt ptxt=None)

        Decrypts a PyCtxt ciphertext into a PyPtxt plaintext.
        
        Decrypts a PyCtxt ciphertext using the current secret key, based on
        the current context. No regard to encoding (decode PyPtxt to obtain 
        value).
        
        Args:
            ctxt (PyCtxt): ciphertext to decrypt. 
            ptxt (PyPtxt, optional): Optional destination plaintext.
            
        Return:
            PyPtxt: the decrypted plaintext
        """
        if ptxt is None:
            ptxt = PyPtxt()
        self.afseal.decrypt(deref(ctxt._ptr_ctxt), deref(ptxt._ptr_ptxt))
        ptxt._encoding = ctxt._encoding
        return ptxt

    # ................................ OTHER ..................................
    cpdef int noiseLevel(self, PyCtxt ctxt) except +:
        """noiseLevel(PyCtxt ctxt)

        Computes the invariant noise budget (bits) of a PyCtxt ciphertext.
        
        The invariant noise budget measures the amount of room there is
        for thenoise to grow while ensuring correct decryptions.
        Decrypts a PyCtxt ciphertext using the current secret key, based
        on the current context.
        
        Args:
            ctxt (PyCtxt): ciphertext to be measured.
            
        Return:
            int: the noise budget level
        """
        return self.afseal.noiseLevel(deref(ctxt._ptr_ctxt))

    cpdef void rotateKeyGen(self, int bitCount) except +:
        """rotateKeyGen(int bitCount)

        Generates a rotation Key.
        
        Generates a rotation Key, used in BATCH mode to rotate cyclically 
        the values inside the encrypted vector.
        
        Based on the current context, initializes one rotation key. 
        
        Args:
            bitCount (int): Bigger means faster but noisier (will require
                            relinearization). Needs to be within [1, 60]
                      
        Return:
            None
        """
        self.afseal.rotateKeyGen(bitCount)

    cpdef void relinKeyGen(self) except +:
        """relinKeyGen()

        Generates a relinearization Key.
        
        Generates a relinearization Key, used to reduce size of the
        ciphertexts when multiplying or exponentiating them. This is needed
        due to the fact that ciphertexts grow in size after encrypted
        mults/exponentiations.
        
        Based on the current context, initializes one relinearization key.        
        
        Return:
            None
        """
        self.afseal.relinKeyGen()

    cpdef void relinearize(self, PyCtxt ctxt) except +:
        """relinearize(PyCtxt ctxt)

        Relinearizes a ciphertext.
        
        Relinearizes a ciphertext. This functions relinearizes ctxt,
        reducing its size down to 2. If the size of encrypted is K+1, the
        given evaluation keys need to have size at least K-1. 
        
        To relinearize a ciphertext of size M >= 2 back to size 2, we
        actually need M-2 evaluation keys. Attempting to relinearize a too
        large ciphertext with too few evaluation keys will result in an
        exception being thrown.
                
        Args:
            bitCount (int): The bigger the faster but noisier (will require
                            relinearization). Needs to be within [1, 60]
                      
        Return:
            None
        """
        self.afseal.relinearize(deref(ctxt._ptr_ctxt))

    cpdef void rescale_to_next(self, PyCtxt ctxt) except +:
        """rescale_to_next(PyCtxt ctxt)

        Rescales a ciphertext to the next scale

        Rescales a ciphertext.           

        Return:
            None
        """
        self.afseal.rescale_to_next(deref(ctxt._ptr_ctxt))

    cpdef void mod_switch_to_nextCtxt(self, PyCtxt ctxt) except +:
        """mod_switch_to_next(PyCtxt ctxt)

        Rescales a ciphertext to the next scale

        Rescales a ciphertext.           

        Return:
            None
        """
        self.afseal.mod_switch_to_next(deref(ctxt._ptr_ctxt))

    cpdef void mod_switch_to_nextPtxt(self, PyPtxt ptxt) except +:
        """mod_switch_to_next(PyPtxt ptxt)

        Rescales a ciphertext to the next scale

        Rescales a ciphertext.           

        Return:
            None
        """
        self.afseal.mod_switch_to_next(deref(ptxt._ptr_ptxt))

    def mod_switch_to_next(self, other):
        if isinstance(other, PyCtxt):
            self.mod_switch_to_nextCtxt(other)
        elif isinstance(other, PyPtxt):
            self.mod_switch_to_nextPtxt(other)

    # =========================================================================
    # ============================== ENCODING =================================
    # =========================================================================
    # ............................... ENCODE ..................................

    cpdef PyPtxt encode(self, double value, double scale, PyPtxt ptxt=None) except +:
        """encode(double &value, double scale, PyPtxt ptxt=None)

        Encodes a single float value into a PyPtxt plaintext.
        
        Encodes a single float value based on the current context.
        If provided a plaintext, encodes the value inside it. 
        
        Args:
            value (float): value to encode.
            scale (float): scale to use.
            ptxt (PyPtxt, optional): Optional destination plaintext.   
            
        Return:
            PyPtxt: the plaintext containing the encoded value
        """
        if ptxt is None:
            ptxt = PyPtxt()
        self.afseal.encode(value, scale, deref(ptxt._ptr_ptxt))
        ptxt._encoding = ENCODING_T.FRACTIONAL
        return ptxt

    cpdef PyPtxt encodeVector(self, vector[double]& vec, double scale, PyPtxt ptxt=None) except +:
        """encodeVector(vector[double]& vec, double scale, PyPtxt ptxt=None)

        Encodes a 1D list of doubles into a PyPtxt plaintext.
        
        Encodes a 1D vector of floats based on the current context.
        Plaintext must be a 1D vector of integers. Requires batch mode.
        In Numpy the vector needs to be in 'contiguous' or 'c' mode.
        If provided a plaintext, encodes the vector inside it. 
        Maximum size of the vector defined by parameter 'm' from context.
        
        Args:
            vec (list[int]): vector to encode.
            scale (float): scale to use.
            ptxt (PyPtxt, optional): Optional destination plaintext.  
            
        Return:
            PyPtxt: the plaintext containing the encoded vector.
        """
        if ptxt is None:
            ptxt = PyPtxt()
        self.afseal.encode(vec, scale, deref(ptxt._ptr_ptxt))
        ptxt._encoding = ENCODING_T.BATCH
        return ptxt

    cpdef PyPtxt encodeComplexVector(self, vector[cpp_complex[double]]& vec, double scale, PyPtxt ptxt=None) except +:
        """encodeVector(vector[double]& vec, double scale, PyPtxt ptxt=None)

        Encodes a 1D list of doubles into a PyPtxt plaintext.

        Encodes a 1D vector of floats based on the current context.
        Plaintext must be a 1D vector of integers. Requires batch mode.
        In Numpy the vector needs to be in 'contiguous' or 'c' mode.
        If provided a plaintext, encodes the vector inside it. 
        Maximum size of the vector defined by parameter 'm' from context.

        Args:
            vec (list[int]): vector to encode.
            scale (float): scale to use.
            ptxt (PyPtxt, optional): Optional destination plaintext.  

        Return:
            PyPtxt: the plaintext containing the encoded vector.
        """
        if ptxt is None:
            ptxt = PyPtxt()
        self.afseal.encode(vec, scale, deref(ptxt._ptr_ptxt))
        ptxt._encoding = ENCODING_T.BATCH
        return ptxt

        # ................................ DECODE .................................

    cpdef vector[double] decode(self, PyPtxt ptxt) except +:
        """decode(PyPtxt ptxt)

        Decodes a PyPtxt plaintext into a vector of float values.
        
        Decodes a PyPtxt plaintext into a vector of float value based on
        the current context.
        
        Args:
            ptxt (PyPtxt): plaintext to decode.
            
        Return:
            list[float]: the decoded float values
            
        """
        cdef vector[double] output_value = [0]
        self.afseal.decode(deref(ptxt._ptr_ptxt), output_value)
        return output_value

    cpdef vector[cpp_complex[double]] decodeComplex(self, PyPtxt ptxt) except +:
        """decode(PyPtxt ptxt)

        Decodes a PyPtxt plaintext into a vector of float values.

        Decodes a PyPtxt plaintext into a vector of float value based on
        the current context.

        Args:
            ptxt (PyPtxt): plaintext to decode.

        Return:
            list[float]: the decoded float values

        """
        cdef vector[cpp_complex[double]] output_value = vector[cpp_complex[double]](0)
        self.afseal.decode(deref(ptxt._ptr_ptxt), output_value)
        return output_value

    # =========================================================================
    # ============================= OPERATIONS ================================
    # =========================================================================
    cpdef PyCtxt square(self, PyCtxt ctxt, bool in_new_ctxt=False) except +:
        """square(PyCtxt ctxt, bool in_new_ctxt=False)

        Square PyCtxt ciphertext value/s.
    
        Args:
            ctxt (PyCtxt): ciphertext whose values are squared.  
            in_new_ctxt (bool): result in a newly created ciphertext
        Return:
            PyCtxt: resulting ciphertext, the input transformed or a new one
        """
        if (in_new_ctxt):
            new_ctxt = PyCtxt(ctxt)
            self.afseal.square(deref(new_ctxt._ptr_ctxt))
            return new_ctxt
        else:
            self.afseal.square(deref(ctxt._ptr_ctxt))
            return ctxt

    cpdef PyCtxt negate(self, PyCtxt ctxt, bool in_new_ctxt=False) except +:
        """negate(PyCtxt ctxt, bool in_new_ctxt=False)

        Negate PyCtxt ciphertext value/s.
    
        Args:
            ctxt (PyCtxt): ciphertext whose values are negated.   
            in_new_ctxt (bool): result in a newly created ciphertext
            
        Return:
            PyCtxt: resulting ciphertext, the input transformed or a new one
        """
        if (in_new_ctxt):
            new_ctxt = PyCtxt(ctxt)
            self.afseal.negate(deref(new_ctxt._ptr_ctxt))
            return new_ctxt
        else:
            self.afseal.negate(deref(ctxt._ptr_ctxt))
            return ctxt

    cpdef PyCtxt add(self, PyCtxt ctxt, PyCtxt ctxt_other, bool in_new_ctxt=False) except +:
        """add(PyCtxt ctxt, PyCtxt ctxt_other, bool in_new_ctxt=False)

        Sum two PyCtxt ciphertexts homomorphically.
        
        Sums two ciphertexts. Encoding must be the same. Requires same
        context and encryption with same public key. The result is applied
        to the first ciphertext.
    
        Args:
            ctxt (PyCtxt): ciphertext whose values are added with ctxt_other.  
            ctxt_other (PyCtxt): ciphertext left untouched.  
            in_new_ctxt (bool): result in a newly created ciphertext
            
        Return:
            PyCtxt: resulting ciphertext, the input transformed or a new one
        """
        if (ctxt._encoding != ctxt_other._encoding):
            raise RuntimeError(f"<Pyfhel ERROR> encoding type mistmatch in add terms"
                               " ({ctxt._encoding} VS {ctxt_other._encoding})")
        if (in_new_ctxt):
            new_ctxt = PyCtxt(ctxt)
            self.afseal.add(deref(new_ctxt._ptr_ctxt), deref(ctxt_other._ptr_ctxt))
            return new_ctxt
        else:
            self.afseal.add(deref(ctxt._ptr_ctxt), deref(ctxt_other._ptr_ctxt))
            return ctxt

    cpdef PyCtxt add_plain(self, PyCtxt ctxt, PyPtxt ptxt, bool in_new_ctxt=False) except +:
        """add_plain(PyCtxt ctxt, PyPtxt ptxt, bool in_new_ctxt=False)

        Sum a PyCtxt ciphertext and a PyPtxt plaintext.
        
        Sums a ciphertext and a plaintext. Encoding must be the same. 
        Requiressame context and encryption with same public key. The result
        is applied to the first ciphertext.
    
        Args:
            ctxt (PyCtxt): ciphertext whose values are added with ptxt.  
            ptxt (PyPtxt): plaintext left untouched.  
            in_new_ctxt (bool): result in a newly created ciphertext
            
        Return:
            PyCtxt: resulting ciphertext, the input transformed or a new one
        """
        if (ctxt._encoding != ptxt._encoding):
            raise RuntimeError("<Pyfhel ERROR> encoding type mistmatch in add terms"
                               " ({ctxt._encoding} VS {ptxt._encoding})")
        if (in_new_ctxt):
            new_ctxt = PyCtxt(ctxt)
            self.afseal.add(deref(new_ctxt._ptr_ctxt), deref(ptxt._ptr_ptxt))
            return new_ctxt
        else:
            self.afseal.add(deref(ctxt._ptr_ctxt), deref(ptxt._ptr_ptxt))
            return ctxt

    cpdef PyCtxt sub(self, PyCtxt ctxt, PyCtxt ctxt_other, bool in_new_ctxt=False) except +:
        """sub(PyCtxt ctxt, PyCtxt ctxt_other, bool in_new_ctxt=False)

        Substracts one PyCtxt ciphertext from another.
        
        Substracts one ciphertext from another. Encoding must be the same.
        Requires same context and encryption with same public key.
        The result is stored/applied to the first ciphertext.
    
        Args:
            ctxt (PyCtxt): ciphertext substracted by ctxt_other.    
            ctxt_other (PyCtxt): ciphertext being substracted from ctxt.
            in_new_ctxt (bool): result in a newly created ciphertext
            
        Return:
            PyCtxt: resulting ciphertext, the input transformed or a new one
        """
        if (ctxt._encoding != ctxt_other._encoding):
            raise RuntimeError("<Pyfhel ERROR> encoding type mistmatch in sub terms"
                               " ({ctxt._encoding} VS {ctxt_other._encoding})")
        if (in_new_ctxt):
            new_ctxt = PyCtxt(ctxt)
            self.afseal.sub(deref(new_ctxt._ptr_ctxt), deref(ctxt_other._ptr_ctxt))
            return new_ctxt
        else:
            self.afseal.sub(deref(ctxt._ptr_ctxt), deref(ctxt_other._ptr_ctxt))
            return ctxt

    cpdef PyCtxt sub_plain(self, PyCtxt ctxt, PyPtxt ptxt, bool in_new_ctxt=False) except +:
        """sub_plain (PyCtxt ctxt, PyPtxt ptxt, bool in_new_ctxt=False)

        Substracts a PyCtxt ciphertext and a plaintext.
        
        Performs ctxt = ctxt - ptxt. Encoding must be the same. Requires 
        same context and encryption with same public key. The result is 
        stored/applied to the ciphertext.
    
        Args:
            ctxt (PyCtxt): ciphertext substracted by ptxt.   
            * ptxt (PyPtxt): plaintext substracted from ctxt.
            in_new_ctxt (bool): result in a newly created ciphertext
            
        Return:
            PyCtxt: resulting ciphertext, the input transformed or a new one
        """
        if (ctxt._encoding != ptxt._encoding):
            raise RuntimeError("<Pyfhel ERROR> encoding type mistmatch in sub terms"
                               " ({ctxt._encoding} VS {ptxt._encoding})")

        if (in_new_ctxt):
            new_ctxt = PyCtxt(ctxt)
            self.afseal.sub(deref(new_ctxt._ptr_ctxt), deref(ptxt._ptr_ptxt))
            return new_ctxt
        else:
            self.afseal.sub(deref(ctxt._ptr_ctxt), deref(ptxt._ptr_ptxt))
            return ctxt

    cpdef PyCtxt multiply(self, PyCtxt ctxt, PyCtxt ctxt_other, bool in_new_ctxt=False) except +:
        """multiply (PyCtxt ctxt, PyCtxt ctxt_other, bool in_new_ctxt=False)

        Multiply first PyCtxt ciphertext by the second PyCtxt ciphertext.
        
        Multiplies two ciphertexts. Encoding must be the same. Requires 
        same context and encryption with same public key. The result is 
        applied to the first ciphertext.
    
        Args:
            ctxt (PyCtxt): ciphertext multiplied with ctxt_other.   
            ctxt_other (PyCtxt): ciphertext left untouched.  
            in_new_ctxt (bool): result in a newly created ciphertext.
            
        Return:
            PyCtxt: resulting ciphertext, the input transformed or a new one
        """
        if (ctxt._encoding != ctxt_other._encoding):
            raise RuntimeError("<Pyfhel ERROR> encoding type mistmatch in mult terms"
                               " ({ctxt._encoding} VS {ctxt_other._encoding})")

        if (in_new_ctxt):
            new_ctxt = PyCtxt(ctxt)
            self.afseal.multiply(deref(new_ctxt._ptr_ctxt), deref(ctxt_other._ptr_ctxt))
            return new_ctxt
        else:
            self.afseal.multiply(deref(ctxt._ptr_ctxt), deref(ctxt_other._ptr_ctxt))
            return ctxt

    cpdef PyCtxt multiply_plain(self, PyCtxt ctxt, PyPtxt ptxt, bool in_new_ctxt=False) except +:
        """multiply_plain (PyCtxt ctxt, PyPtxt ptxt, bool in_new_ctxt=False)

        Multiply a PyCtxt ciphertext and a PyPtxt plaintext.
        
        Multiplies a ciphertext and a plaintext. Encoding must be the same. 
        Requires same context and encryption with same public key. The 
        result is applied to the first ciphertext.
    
        Args:
            ctxt (PyCtxt): ciphertext whose values are multiplied with ptxt.  
            ptxt (PyPtxt): plaintext left untouched.  
            
        Return:
            PyCtxt: resulting ciphertext, either the input transformed or a new one
        """
        if (ctxt._encoding != ptxt._encoding):
            raise RuntimeError("<Pyfhel ERROR> encoding type mistmatch in mult terms"
                               " ({ctxt._encoding} VS {ptxt._encoding})")
        if (in_new_ctxt):
            new_ctxt = PyCtxt(ctxt)
            self.afseal.multiply(deref(new_ctxt._ptr_ctxt), deref(ptxt._ptr_ptxt))
            return new_ctxt
        else:
            self.afseal.multiply(deref(ctxt._ptr_ctxt), deref(ptxt._ptr_ptxt))
            return ctxt

    cpdef PyCtxt rotate(self, PyCtxt ctxt, int k, bool in_new_ctxt=False) except +:
        """rotate(PyCtxt ctxt, int k, bool in_new_ctxt=False)

        Rotates cyclically PyCtxt ciphertext values k positions.
        
        Performs a cyclic rotation over a cyphertext encoded in BATCH mode. 
        Requires previously initialized rotation keys with rotateKeyGen().
    
        Args:
            ctxt (PyCtxt): ciphertext whose values are rotated.
            k (int): number of positions to rotate.
            in_new_ctxt (bool): result in a newly created ciphertext
            
        Return:
            PyCtxt: resulting ciphertext, the input transformed or a new one
        """
        if (in_new_ctxt):
            new_ctxt = PyCtxt(ctxt)
            self.afseal.rotate(deref(new_ctxt._ptr_ctxt), k)
            return new_ctxt
        else:
            self.afseal.rotate(deref(ctxt._ptr_ctxt), k)
            return ctxt

    cpdef PyCtxt power(self, PyCtxt ctxt, uint64_t expon, bool in_new_ctxt=False) except +:
        """power(PyCtxt ctxt, int expon, bool in_new_ctxt=False)

        Exponentiates PyCtxt ciphertext value/s to expon power.
        
        Performs an exponentiation over a cyphertext. Requires previously
        initialized relinearization keys with relinearizeKeyGen(), since
        it applies relinearization after each multiplication.
    
        Args:
            ctxt (PyCtxt): ciphertext whose value/s are exponetiated.  
            expon (int): exponent.
            in_new_ctxt (bool): result in a newly created ciphertext
            
        Return:
            PyCtxt: resulting ciphertext, the input transformed or a new one
        """
        if (in_new_ctxt):
            new_ctxt = PyCtxt(ctxt)
            self.afseal.exponentiate(deref(new_ctxt._ptr_ctxt), expon)
            return new_ctxt
        else:
            self.afseal.exponentiate(deref(ctxt._ptr_ctxt), expon)
            return ctxt

    cpdef PyCtxt polyEval(self, PyCtxt ctxt,
                          vector[int64_t] coeffPoly, bool in_new_ctxt=False) except +:
        """polyEval(PyCtxt ctxt, vector[int64_t] coeffPoly, bool in_new_ctxt=False)

        Evaluates polynomial in PyCtxt ciphertext value/s.
        
        Evaluates a polynomial given by integer coefficients. Requires 
        previously initialized relinearization keys with
        relinearizeKeyGen(), since it applies relinearization after
        each multiplication.
    
        Polynomial coefficients are in the form:
            coeffPoly[0]*ctxt^2 + coeffPoly[1]*ctxt + coeffPoly[2]

        Args:
            ctxt (PyCtxt): ciphertext whose value/s are exponetiated.  
            coeffPoly (list[int]): Polynomial coefficients
            in_new_ctxt (bool): result in a newly created ciphertext
            
        Return:
            PyCtxt: resulting ciphertext, the input transformed or a new one
        """

        if (ctxt._encoding != ENCODING_T.BATCH) and (ctxt._encoding != ENCODING_T.INTEGER):
            raise RuntimeError("<Pyfhel ERROR> encoding type must be INTEGER or BATCH")
        if (in_new_ctxt):
            new_ctxt = PyCtxt(ctxt)
            self.afseal.polyEval(deref(new_ctxt._ptr_ctxt), coeffPoly)
            return new_ctxt
        else:
            self.afseal.polyEval(deref(ctxt._ptr_ctxt), coeffPoly)
            return ctxt

    cpdef PyCtxt polyEval_double(self, PyCtxt ctxt,
                                 vector[double] coeffPoly, bool in_new_ctxt=False) except +:
        """polyEval_double (PyCtxt ctxt, vector[double] coeffPoly, bool in_new_ctxt=False)

        Evaluates polynomial in PyCtxt ciphertext value/s.
        
        Evaluates a polynomial given by float coefficients. Requires 
        previously initialized relinearization keys with relinearizeKeyGen(),
        since it applies relinearization after each multiplication.
    
        Polynomial coefficients are in the form:
            coeffPoly[0]*ctxt^2 + coeffPoly[1]*ctxt + coeffPoly[2]

        Args:
            ctxt (PyCtxt): ciphertext whose value/s are exponetiated.  
            coeffPoly (list[int]): Polynomial coefficients. 
            in_new_ctxt (bool): result in a newly created ciphertext
            
        Return:
            PyCtxt: resulting ciphertext, the input transformed or a new one
        """
        if (ctxt._encoding != ENCODING_T.BATCH) and (ctxt._encoding != ENCODING_T.INTEGER):
            raise RuntimeError("<Pyfhel ERROR> encoding type must be INTEGER or BATCH")
        if (in_new_ctxt):
            new_ctxt = PyCtxt(ctxt)
            self.afseal.polyEval(deref(new_ctxt._ptr_ctxt), coeffPoly)
            return new_ctxt
        else:
            self.afseal.polyEval(deref(ctxt._ptr_ctxt), coeffPoly)
            return ctxt

    # =========================================================================
    # ================================ I/O ====================================
    # =========================================================================   

    # FILES

    cpdef bool saveContext(self, fileName) except +:
        """saveContext(fileName)

        Saves current context in a file
        
        Args:
            fileName (str, pathlib.Path): Name of the file.   
            
        Return:
            bool: Result, True if OK, False otherwise.
        """
        return self.afseal.saveContext(_to_valid_file_str(fileName, check=False).encode())

    cpdef bool restoreContext(self, fileName) except +:
        """restoreContext(fileName)

        Restores current context from a file
        
        Args:
            fileName (str, pathlib.Path): Name of the file.   
            
        Return:
            bool: Result, True if OK, False otherwise.
        """
        return self.afseal.restoreContext(_to_valid_file_str(fileName, check=True).encode())

    cpdef bool savepublicKey(self, fileName) except +:
        """savepublicKey(fileName)

        Saves current public key in a file
        
        Args:
            fileName (str, pathlib.Path): Name of the file.   
            
        Return:
            bool: Result, True if OK, False otherwise.
        """
        return self.afseal.savepublicKey(_to_valid_file_str(fileName, check=False).encode())

    cpdef bool restorepublicKey(self, fileName) except +:
        """restorepublicKey(fileName)

        Restores current public key from a file
        
        Args:
            fileName (str, pathlib.Path): Name of the file.   
            
        Return:
            bool: Result, True if OK, False otherwise.
        """
        return self.afseal.restorepublicKey(_to_valid_file_str(fileName, check=True).encode())

    cpdef bool savesecretKey(self, fileName) except +:
        """savesecretKey(fileName)

        Saves current secret key in a file
        
        Args:
            fileName (str, pathlib.Path): Name of the file.   
            
        Return:
            bool: Result, True if OK, False otherwise.
        """
        return self.afseal.savesecretKey(_to_valid_file_str(fileName, check=False).encode())

    cpdef bool restoresecretKey(self, fileName) except +:
        """restoresecretKey(fileName)

        Restores current secret key from a file
        
        Args:
            fileName (str, pathlib.Path): Name of the file.   
            
        Return:
            bool: Result, True if OK, False otherwise.
        """
        return self.afseal.restoresecretKey(_to_valid_file_str(fileName, check=True).encode())

    cpdef bool saverelinKey(self, fileName) except +:
        """saverelinKey(fileName)

        Saves current relinearization keys in a file
        
        Args:
            fileName (str, pathlib.Path): Name of the file.   
            
        Return:
            bool: Result, True if OK, False otherwise.
        """
        return self.afseal.saverelinKey(_to_valid_file_str(fileName, check=False).encode())

    cpdef bool restorerelinKey(self, fileName) except +:
        """restorerelinKey(fileName)

        Restores current relinearization keys from a file
        
        Args:
            fileName (str, pathlib.Path): Name of the file.   
            
        Return:
            bool: Result, True if OK, False otherwise.
        """
        return self.afseal.restorerelinKey(_to_valid_file_str(fileName, check=True).encode())

    cpdef bool saverotateKey(self, fileName) except +:
        """saverotateKey(fileName)

        Saves current rotation Keys from a file
        
        Args:
            fileName (str, pathlib.Path): Name of the file.   
            
        Return:
            bool: Result, True if OK, False otherwise.
        """
        return self.afseal.saverotateKey(_to_valid_file_str(fileName, check=False).encode())

    cpdef bool restorerotateKey(self, fileName) except +:
        """restorerotateKey(fileName)

        Restores current rotation Keys from a file
        
        Args:
            fileName (str, pathlib.Path): Name of the file.   
            
        Return:
            bool: Result, True if OK, False otherwise.
        """
        return self.afseal.restorerotateKey(_to_valid_file_str(fileName, check=True).encode())

    # BYTES

    cpdef bytes to_bytes_context(self) except +:
        """to_bytes_Context()

        Saves current context in a bytes string
        
        Args:
            None  
            
        Return:
            bytes: Serialized Context.
        """
        cdef ostringstream outputter
        self.afseal.ssaveContext(outputter)
        return outputter.str()

    cpdef bool from_bytes_context(self, bytes content) except +:
        """from_bytes_context(bytes content)

        Restores current context from a bytes object
        
        Args:
            content (bytes): bytes object obtained from to_bytes_context   
            
        Return:
            bool: Result, True if OK, False otherwise.
        """
        cdef stringstream inputter
        inputter.write(content, len(content))
        return self.afseal.srestoreContext(inputter)

    cpdef bytes to_bytes_publicKey(self) except +:
        """to_bytes_publicKey()

        Saves current public key in a bytes string
        
        Args:
            None  
            
        Return:
            bytes: Serialized public key.
        """
        cdef ostringstream outputter
        self.afseal.ssavepublicKey(outputter)
        return outputter.str()

    cpdef bool from_bytes_publicKey(self, bytes content) except +:
        """from_bytes_publicKey(bytes content)

        Restores current public key from a bytes object
        
        Args:
            content (bytes): bytes object obtained from to_bytes_publicKey   
            
        Return:
            bool: Result, True if OK, False otherwise.
        """
        cdef stringstream inputter
        inputter.write(content, len(content))
        return self.afseal.srestorepublicKey(inputter)

    cpdef bytes to_bytes_secretKey(self) except +:
        """to_bytes_secretKey()

        Saves current secret key in a bytes string
        
        Args:
            None  
            
        Return:
            bytes: Serialized secret key.
        """
        cdef ostringstream outputter
        self.afseal.ssavesecretKey(outputter)
        return outputter.str()

    cpdef bool from_bytes_secretKey(self, bytes content) except +:
        """from_bytes_secretKey(bytes content)

        Restores current secret key from a bytes object
        
        Args:
            content (bytes): bytes object obtained from to_bytes_secretKey   
            
        Return:
            bool: Result, True if OK, False otherwise.
        """
        cdef stringstream inputter
        inputter.write(content, len(content))
        return self.afseal.srestoresecretKey(inputter)

    cpdef bytes to_bytes_relinKey(self) except +:
        """to_bytes_relinKey()

        Saves current relinearization key in a bytes string
        
        Args:
            None  
            
        Return:
            bytes: Serialized relinearization key.
        """
        cdef ostringstream outputter
        self.afseal.ssaverelinKey(outputter)
        return outputter.str()

    cpdef bool from_bytes_relinKey(self, bytes content) except +:
        """from_bytes_relinKey(bytes content)

        Restores current relin key from a bytes object
        
        Args:
            content (bytes): bytes object obtained from to_bytes_relinKey   
            
        Return:
            bool: Result, True if OK, False otherwise.
        """
        cdef stringstream inputter
        inputter.write(content, len(content))
        return self.afseal.srestorerelinKey(inputter)

    cpdef bytes to_bytes_rotateKey(self) except +:
        """to_bytes_rotateKey(fileName)

        Saves current context in a bytes string
        
        Args:
            None  
            
        Return:
            bytes: Serialized rotation key.
        """
        cdef ostringstream outputter
        self.afseal.ssaverotateKey(outputter)
        return outputter.str()

    cpdef bool from_bytes_rotateKey(self, bytes content) except +:
        """from_bytes_rotateKey(bytes content)

        Restores current rotation key from a bytes object
        
        Args:
            content (bytes): bytes object obtained from to_bytes_rotateKey   
            
        Return:
            bool: Result, True if OK, False otherwise.
        """
        cdef stringstream inputter
        inputter.write(content, len(content))
        return self.afseal.srestorerotateKey(inputter)

    # =========================================================================
    # ============================== AUXILIARY ================================
    # =========================================================================
    def multDepth(self, max_depth=64, delta=0.1, x_y_z=(1, 10, 0.1), verbose=False):
        """multDepth(max_depth=64, delta=0.1, x_y_z=(1, 10, 0.1), verbose=False)

        Empirically determines the multiplicative depth of a Pyfhel Object
        for a given context. For this, it encrypts the inputs x, y and z with
        Fractional encoding and performs the following chained multiplication
        until the result deviates more than delta in absolute value:
        
        >    x * y * z * y * z * y * z * y * z ...

        After each multiplication, the ciphertext is relinearized and checked.
        Ideally, y and z should be inverses to avoid wrapping over modulo p.
        Requires the Pyfhel Object to have initialized context and pub/sec/relin keys.
        """
        x, y, z = x_y_z
        cx = self.encryptFrac(x)
        cy = self.encryptFrac(y)
        cz = self.encryptFrac(z)
        for m_depth in range(1, max_depth + 1):
            if m_depth % 2:  # Multiply by y and relinearize
                x *= y
                cx *= cy
            else:  # Multiply by z and relinearize
                x *= z
                cx *= cz
            ~cx  # Relinearize after every multiplication
            x_hat = self.decryptFrac(cx)
            if verbose:
                print(f'Mult {m_depth} [budget: {self.noiseLevel(cx)} dB]: {x_hat} (expected {x})')
            if abs(x - x_hat) > delta:
                break
        return m_depth

    cpdef long relinBitCount(self) except +:
        """relinBitCount()

        Relinearization bit count for current evaluation keys.
            
        Return:
            int: [1-60], based on relinKeyGen parameter.
        """
        return self.afseal.relinBitCount()

    cpdef long maxBitCount(self, long n, int sec_level) except +:
        """maxBitCount()

        Maximum number of bits in all qi's that we can have with degree n and sec_level bit security

        Return:
            long
        """
        return self.afseal.maxBitCount(n, sec_level)

    cpdef double scale(self, PyCtxt ctxt) except +:
        return self.afseal.scale(deref(ctxt._ptr_ctxt))

    cpdef void set_scale(self, PyCtxt ctxt, double scale) except +:
        self.afseal.override_scale(deref(ctxt._ptr_ctxt), scale)

    # GETTERS
    cpdef int getnSlots(self) except +:
        """Maximum number of slots fitting in a ciphertext in BATCH mode.
        
        Generally it matches with `m`.

        Return:
            int: Maximum umber of slots.
        """
        return self.afseal.getnSlots()

    cpdef int getm(self) except +:
        """Plaintext coefficient of the current context.
        
        The more, the bigger the ciphertexts are, thus allowing for 
        more operations with correct decryption. Also, number of 
        values in a ciphertext in BATCH encoding mode. 
        
            
        Return:
            int: Plaintext coefficient.
        """
        return self.afseal.getm()

    cpdef int getbase(self) except +:
        """Polynomial base.
        
        Polynomial base of polynomials that conform cyphertexts and 
        plaintexts.Affects size of plaintexts and ciphertexts, and 
        FRACTIONAL encoding. See encryptFrac. 
        
        Return:
            int: Polynomial base.
        """
        return self.afseal.getbase()

    cpdef int getsec(self) except +:
        """Security level equivalent in AES.
        
        Return:
            int: Security level equivalent in AES. Either 128 or 192.
        """
        return self.afseal.getsec()

    cpdef int getintDigits(self) except +:
        """Integer digits in FRACTIONAL encoding.
        
        When encrypting/encoding double (FRACTIONAL encoding), truncated
        positions dedicated to integer part, out of 'm' positions.
        
        Return:
            int: number of integer digits.
        """
        return self.afseal.getintDigits()

    cpdef int getfracDigits(self) except +:
        """Decimal digits in FRACTIONAL encoding.
        
        When encrypting/encoding double (FRACTIONAL encoding), truncated
        positions dedicated to deimal part, out of 'm' positions.
        
        Return:
            int: number of fractional digits.
        """
        return self.afseal.getfracDigits()

    cpdef bool getflagBatch(self) except +:
        """Flag for BATCH encoding mode.
        
        If True, allows operations over vectors encrypted in single PyCtxt 
        ciphertexts. Defined in context creation based on the chosen values
        of p and m, and activated in context creation with a flag.
        
        Return:
            bool: flag for enabled BATCH encoding and operating.
        """
        return self.afseal.getflagBatch()

    cpdef bool is_secretKey_empty(self) except+:
        """True if the current Pyfhel instance has no secret Key.

        Return:
            bool: True if there is no secret Key. False if there is.
        """
        return self.afseal.is_secretKey_empty()

    cpdef bool is_publicKey_empty(self) except+:
        """True if the current Pyfhel instance has no public Key.

        Return:
            bool: True if there is no public Key. False if there is.
        """
        return self.afseal.is_publicKey_empty()

    cpdef bool is_rotKey_empty(self) except+:
        """True if the current Pyfhel instance has no rotation key.

        Return:
            bool: True if there is no rotation Key. False if there is.
        """
        return self.afseal.is_rotKey_empty()

    cpdef bool is_relinKey_empty(self) except+:
        """True if the current Pyfhel instance has no relinearization key.

        Return:
            bool: True if there is no relinearization Key. False if there is.
        """
        return self.afseal.is_relinKey_empty()

    cpdef bool is_context_empty(self) except+:
        """True if the current Pyfhel instance has no context.

        Return:
            bool: True if there is no context. False if there is.
        """
        return self.afseal.is_context_empty()
