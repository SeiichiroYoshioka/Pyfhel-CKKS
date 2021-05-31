# distutils: language = c++
# distutils: sources = ../SEAL/SEAL/seal/plaintext.cpp ../SEAL/SEAL/seal/ciphertext.cpp ../Afhel/Afseal.cpp
#cython: language_level=3, boundscheck=False

# -------------------------------- IMPORTS ------------------------------------
# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.vector cimport vector
from libcpp.string cimport string
from libcpp cimport bool
from numpy cimport int64_t, uint64_t

# Import our own wrapper for iostream classes, used for I/O ops
from Pyfhel.iostream cimport istream, ostream, ifstream, ofstream


# --------------------------- EXTERN DECLARATION ------------------------------
# SEAL plaintext class        
cdef extern from "SEAL/SEAL/seal/plaintext.h" namespace "seal" nogil:
    cdef cppclass Plaintext:
        Plaintext() except +
        Plaintext(const Plaintext & copy) except +
        bool is_zero() except +
        string to_string() except +
        void save(ostream & stream) except +
        void load(istream & stream) except +

# SEAL ciphertext class        
cdef extern from "SEAL/SEAL/seal/ciphertext.h" namespace "seal" nogil:
    cdef cppclass Ciphertext:
        Ciphertext() except +
        Ciphertext(const Ciphertext & copy) except +
        int size_capacity() except +
        int size() except +
        void save(ostream & stream) except +
        void load(istream & stream) except +

# Afseal class to abstract SEAL
cdef extern from "Afhel/Afseal.h" nogil:
    cdef cppclass Afseal:
        # ----------------------- OBJECT MANAGEMENT ---------------------------
        Afseal() except +
        Afseal(const Afseal & otherAfseal) except +
        Afseal(Afseal & & source) except +

        # -------------------------- CRYPTOGRAPHY -----------------------------
        # CONTEXT & KEY GENERATION
        void ContextGen(long m, bool flagBatching, long base,
                        long sec, int intDigits, int fracDigits, vector[int] qs) except +
        void KeyGen() except +

        # ENCRYPTION
        Ciphertext encrypt(Plaintext& plain1) except +
        void encrypt(Plaintext& plain1, Ciphertext& cipherOut) except +

        # DECRYPTION
        Plaintext decrypt(Ciphertext& cipher1) except +
        void decrypt(Ciphertext& cipher1, Plaintext& plainOut) except +

        # NOISE LEVEL
        int noiseLevel(Ciphertext& cipher1) except +

        # ------------------------------ CODEC --------------------------------
        # ENCODE
        Plaintext encode(double& value1, double scale) except +
        Plaintext encode(vector[double] & values, double scale) except +
        void encode(double& value1, double scale, Plaintext& plainOut) except +
        void encodeVector(vector[double] & values, double scale, Plaintext& plainVOut) except +

        # DECODE 
        vector[double] decode(Plaintext& plain1) except +

        void decode(Plaintext& plain1, int64_t


        & valOut) except +
        void decode(Plaintext& plain1, vector[double] & valueVOut) except +
        void decode(vector[Plaintext]& plain1, vector[int64_t] & valueVOut) except +

        # -------------------------- OTHER OPERATIONS -------------------------
        void rotateKeyGen(int& bitCount) except +
        void relinKeyGen() except +
        void relinearize(Ciphertext& cipher1) except +

        # ---------------------- HOMOMORPHIC OPERATIONS -----------------------
        void rescale_to_next(Ciphertext& cipher1) except +
        void mod_switch_to_next(Ciphertext& cipher1) except +
        void mod_switch_to_next(Plaintext& ptxt) except +
        void square(Ciphertext& cipher1) except +
        void square(vector[Ciphertext]& cipherV) except +
        void negate(Ciphertext& cipher1) except +
        void negate(vector[Ciphertext]& cipherV) except +
        void add(Ciphertext& cipher1, Ciphertext& cipher2) except +
        void add(Ciphertext& cipher1, Plaintext& plain2) except +
        void add(vector[Ciphertext]& cipherV, Ciphertext& cipherOut) except +
        void add(vector[Ciphertext]& cipherVInOut, vector[Ciphertext]& cipherV2) except +
        void add(vector[Ciphertext]& cipherVInOut, vector[Plaintext]& plainV2) except +
        void sub(Ciphertext& cipher1, Ciphertext& cipher2) except +
        void sub(Ciphertext& cipher1, Plaintext& plain2) except +
        void sub(vector[Ciphertext]& cipherVInOut, vector[Ciphertext]& cipherV2) except +
        void sub(vector[Ciphertext]& cipherVInOut, vector[Plaintext]& plainV2) except +
        void multiply(Ciphertext& cipher1, Ciphertext& cipher2) except +
        void multiply(Ciphertext& cipher1, Plaintext& plain1) except +
        void multiply(vector[Ciphertext]& cipherV1, Ciphertext& cipherOut) except +
        void multiply(vector[Ciphertext]& cipherVInOut, vector[Ciphertext]& cipherV2) except +
        void multiply(vector[Ciphertext]& cipherVInOut, vector[Plaintext]& plainV2) except +
        void rotate(Ciphertext& cipher1, int& k) except +
        void rotate(vector[Ciphertext]& cipherV, int& k) except +
        void exponentiate(Ciphertext& cipher1, uint64_t& expon) except +
        void exponentiate(vector[Ciphertext]& cipherV, uint64_t& expon) except +
        void polyEval(Ciphertext& cipher1, vector[int64_t]& coeffPoly) except +
        void polyEval(Ciphertext& cipher1, vector[double]& coeffPoly) except +

        # -------------------------------- I/O --------------------------------
        bool saveContext(string fileName) except +
        bool restoreContext(string fileName) except +

        bool savepublicKey(string fileName) except +
        bool restorepublicKey(string fileName) except +

        bool savesecretKey(string fileName) except +
        bool restoresecretKey(string fileName) except +

        bool saverelinKey(string fileName) except +
        bool restorerelinKey(string fileName) except +

        bool saverotateKey(string fileName) except +
        bool restorerotateKey(string fileName) except +

        bool ssaveContext(ostream& contextFile) except +
        bool srestoreContext(istream& contextFile) except +

        bool ssavepublicKey(ostream& keyFile) except +
        bool srestorepublicKey(istream& keyFile) except +

        bool ssavesecretKey(ostream& keyFile) except +
        bool srestoresecretKey(istream& keyFile) except +

        bool ssaverelinKey(ostream& keyFile) except +
        bool srestorerelinKey(istream& keyFile) except +

        bool ssaverotateKey(ostream& keyFile) except +
        bool srestorerotateKey(istream& keyFile) except +

        # ----------------------------- AUXILIARY -----------------------------
        bool batchEnabled() except +
        long relinBitCount() except +
        double scale(Ciphertext& ctxt) except +
        void override_scale(Ciphertext& ctxt, double scale)

        # GETTERS
        int getnSlots() except +
        int getm() except +
        int getbase() except +
        int getsec() except +
        int getintDigits() except +
        int getfracDigits() except +
        bool getflagBatch() except +
        bool is_secretKey_empty() except+
        bool is_publicKey_empty() except+
        bool is_rotKey_empty() except+
        bool is_relinKey_empty() except+
        bool is_context_empty() except+
