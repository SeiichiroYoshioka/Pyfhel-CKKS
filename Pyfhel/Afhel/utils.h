// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "../SEAL/SEAL/seal/seal.h"
#include "../SEAL/SEAL/seal/modulus.h"
#include "../SEAL/SEAL/seal/iterator.h"

typedef std::complex<double> cx_double;

/// Generate a random vector of complex numbers with a given size
/// \param array Vector to store results into
/// \param n    Size of vector
/// \param rad  Radius (distance from origin of complex number plane) the complex numbers should have
void randomComplexVector(std::vector<cx_double> &array, size_t n, double rad = 1.0);

/// Find the largest element of a vector
double largestElm(std::vector<cx_double> const &vec);

/// Find the largest element in (in0 - in1), i.e. their largest difference
double maxDiff(std::vector<cx_double> const &in0, std::vector<cx_double> const &in1);

/// Find the relative error (in0-in1)/in1 between two vectors in0 and in1
double relError(std::vector<cx_double> const &in0, std::vector<cx_double> const &in1);

/// Datatype for a seal polynomial. Due to what seems to be a bug in SEAL, these cannot be assigned or copied with =
typedef seal::util::CoeffIter seal_polynomial;

/// Const version of seal_polynomial
typedef seal::util::ConstCoeffIter const_seal_polynomial;

/// copy result = a (this lets you get rid of the "const" in const_seal_polynomial)
/// \param a element to copy
/// \param coeff_count The number of coefficients in the polynomial (i.e., poly_modulus_degree)
/// \param coeff_modulus_count The number of coefficient moduli q_i (i.e., coeff_modulus.size() )
/// \param result Element to store result in
void copy(const_seal_polynomial a, std::size_t coeff_count, std::size_t coeff_modulus_count,
          seal_polynomial result);
/// Converts a polynomial from standard representation into a special representation (FFT/NTT) used for fast evaluation
/// This is the representation ctxts will generally have in SEAL
/// \param a element to convert
/// \param coeff_count The number of coefficients in the polynomial (i.e., poly_modulus_degree)
/// \param coeff_modulus_count The number of coefficient moduli q_i (i.e., coeff_modulus.size() )
/// \param small_ntt_tables special helper (get via context.get_context_data(ctxt.parms_id())->small_ntt_tables())
void to_eval_rep(seal_polynomial a,
                 size_t coeff_count,
                 size_t coeff_modulus_count,
                 seal::util::NTTTables const *small_ntt_tables);

// Converts a polynomial from eval_rep back into standard coefficient representation
/// \param a element to convert
/// \param coeff_count The number of coefficients in the polynomial (i.e., poly_modulus_degree)
/// \param coeff_modulus_count The number of coefficient moduli q_i (i.e., coeff_modulus.size() )
/// \param small_ntt_tables special helper (get via context.get_context_data(ctxt.parms_id())->small_ntt_tables())
void to_coeff_rep(seal_polynomial a,
                  size_t coeff_count,
                  size_t coeff_modulus_count,
                  seal::util::NTTTables const *small_ntt_tables);

/// Infinity norm of a polynomial (must be in standard coefficient representation)
long double infty_norm(const_seal_polynomial a, seal::SEALContext::ContextData const *context_data);

/// L2 norm of a polynomial
long double l2_norm(const_seal_polynomial a, seal::SEALContext::ContextData const *context_data);

/// Compute the multiplicative inverse of a polynomial in the ring (if the inverse exists)
/// \param The element (polynomial) to invert
/// \param coeff_count The number of coefficients in the polynomial (i.e., poly_modulus_degree)
/// \param coeff_modulus The coefficient modulus q
/// \param result Element to store result in
/// \return true if the inverse exists and could be computed
bool inverse(const_seal_polynomial a, std::size_t coeff_count, std::vector<seal::Modulus> const &coeff_modulus,
             seal_polynomial result);

/// compute a*b, requires a and b are in eval_rep form
void multiply(const_seal_polynomial a, const_seal_polynomial b,
              std::size_t coeff_count, std::vector<seal::Modulus> const &coeff_modulus,
              seal_polynomial result);

/// compute a+b, requires a and b are in eval_rep form
void add(const_seal_polynomial a, const_seal_polynomial b,
         std::size_t coeff_count, std::vector<seal::Modulus> const &coeff_modulus,
         seal_polynomial result);

/// compute a-b, requires a and b are in eval_rep form
void sub(const_seal_polynomial a, const_seal_polynomial b,
         std::size_t coeff_count, std::vector<seal::Modulus> const &coeff_modulus,
         seal_polynomial result);

/*
 * Helper function: Allows using a vector in std::cout << some_vector std::endl;
 */
template<typename T>
std::ostream &operator<<(std::ostream &os, const std::vector<T> &v) {
  using namespace std;
  os << "[";
  copy(v.begin(), v.end(), ostream_iterator<T>(os, ", "));
  os << "]";
  return os;
}

/*
Helper function: Prints the parameters in a SEALContext.
*/
inline void print_parameters(const seal::SEALContext &context, double scale) {
  auto &context_data = *context.key_context_data();

  /*
  Which scheme are we using?
  */
  std::string scheme_name;
  switch (context_data.parms().scheme()) {
    case seal::scheme_type::bfv:scheme_name = "BFV";
      break;
    case seal::scheme_type::ckks:scheme_name = "CKKS";
      break;
    default:throw std::invalid_argument("unsupported scheme");
  }
  std::cout << "/" << std::endl;
  std::cout << "| Encryption parameters :" << std::endl;
  std::cout << "|   scheme: " << scheme_name << std::endl;
  std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

  /*
  Print the size of the true (product) coefficient modulus.
  */
  std::cout << "|   coeff_modulus size: ";
  std::cout << context_data.total_coeff_modulus_bit_count() << " (";
  auto coeff_modulus = context_data.parms().coeff_modulus();
  std::size_t coeff_modulus_size = coeff_modulus.size();
  for (std::size_t i = 0; i < coeff_modulus_size - 1; i++) {
    std::cout << coeff_modulus[i].bit_count() << " + ";
  }
  std::cout << coeff_modulus.back().bit_count();
  std::cout << ") bits" << std::endl;

  /*
  For the BFV scheme print the plain_modulus parameter.
  */
  if (context_data.parms().scheme()==seal::scheme_type::bfv) {
    std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
  }

  std::cout << "|   scale: " << log2(scale) << " bits " << std::endl;

  std::cout << "\\" << std::endl;
}

/*
Helper function: Prints the `parms_id' to std::ostream.
*/
inline std::ostream &operator<<(std::ostream &stream, seal::parms_id_type parms_id) {
  /*
  Save the formatting information for std::cout.
  */
  std::ios old_fmt(nullptr);
  old_fmt.copyfmt(std::cout);

  stream << std::hex << std::setfill('0') << std::setw(16) << parms_id[0] << " " << std::setw(16) << parms_id[1]
         << " " << std::setw(16) << parms_id[2] << " " << std::setw(16) << parms_id[3] << " ";

  /*
  Restore the old std::cout formatting.
  */
  std::cout.copyfmt(old_fmt);

  return stream;
}

/*
Helper function: Prints a vector of floating-point values.
*/
template<typename T>
inline void print_vector(std::vector<T> vec, std::size_t print_size = 4, int prec = 3) {
  /*
  Save the formatting information for std::cout.
  */
  std::ios old_fmt(nullptr);
  old_fmt.copyfmt(std::cout);

  std::size_t slot_count = vec.size();

  std::cout << std::fixed << std::setprecision(prec);
  std::cout << std::endl;
  if (slot_count <= 2*print_size) {
    std::cout << "    [";
    for (std::size_t i = 0; i < slot_count; i++) {
      std::cout << " " << vec[i] << ((i!=slot_count - 1) ? "," : " ]\n");
    }
  } else {
    vec.resize(std::max(vec.size(), 2*print_size));
    std::cout << "    [";
    for (std::size_t i = 0; i < print_size; i++) {
      std::cout << " " << vec[i] << ",";
    }
    if (vec.size() > 2*print_size) {
      std::cout << " ...,";
    }
    for (std::size_t i = slot_count - print_size; i < slot_count; i++) {
      std::cout << " " << vec[i] << ((i!=slot_count - 1) ? "," : " ]\n");
    }
  }
  std::cout << std::endl;

  /*
  Restore the old std::cout formatting.
  */
  std::cout.copyfmt(old_fmt);
}

/*
Helper function: Print line number.
*/
inline void print_line(int line_number) {
  std::cout << "Line " << std::setw(3) << line_number << " --> ";
}