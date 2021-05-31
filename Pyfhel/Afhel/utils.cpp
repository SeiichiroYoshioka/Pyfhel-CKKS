#include "utils.h"
#include "../SEAL/SEAL/seal/uintarithsmallmod.h"
#include "../SEAL/SEAL/seal/polyarithsmallmod.h"

using namespace seal;

// compute a^{-1}, where a is a double-CRT polynomial whose evaluation representation
// is in a. The double-CRT representation in SEAL is stored as a flat array of
// length coeff_count * modulus_count:
//    [ 0 .. coeff_count-1 , coeff_count .. 2*coeff_count-1, ... ]
//      ^--- a (mod p0)    , ^--- a (mod p1),              ,  ...
// return if the inverse exists, and result is also in evaluation representation
bool inverse(util::ConstCoeffIter a, std::size_t coeff_count, std::vector<Modulus> const& coeff_modulus,
             util::CoeffIter result) {
  bool * has_inv = new bool[coeff_modulus.size()];
  std::fill_n(has_inv, coeff_modulus.size(), true);
#pragma omp parallel for
  for (size_t j = 0; j < coeff_modulus.size(); j++) {
    for (size_t i = 0; i < coeff_count && has_inv[j]; i++) {
      uint64_t inv = 0;
      if (util::try_invert_uint_mod(a[i + (j * coeff_count)], coeff_modulus[j], inv)) {
        result[i + (j * coeff_count)] = inv;
      } else {
        has_inv[j] = false;
      }
    }
  }
  for (size_t j = 0; j < coeff_modulus.size(); j++) {
    if (!has_inv[j]) return false;
  }
  delete [] has_inv;
  return true;
}

void multiply(util::ConstCoeffIter a, util::ConstCoeffIter b, std::size_t coeff_count,
              std::vector<Modulus> const& coeff_modulus, util::CoeffIter result) {
#pragma omp parallel for
  for (size_t j = 0; j < coeff_modulus.size(); j++) {
    util::dyadic_product_coeffmod(a + (j * coeff_count),
                                  b + (j * coeff_count),
                                  coeff_count,
                                  coeff_modulus[j],
                                  result + (j * coeff_count));
  }
}

void add(util::ConstCoeffIter a, util::ConstCoeffIter b, std::size_t coeff_count,
         std::vector<Modulus> const& coeff_modulus, util::CoeffIter result) {
#pragma omp parallel for
  for (size_t j = 0; j < coeff_modulus.size(); j++) {
    util::add_poly_coeffmod(a + (j * coeff_count),
                            b + (j * coeff_count),
                            coeff_count,
                            coeff_modulus[j],
                            result + (j * coeff_count));
  }
}

void sub(util::ConstCoeffIter a, util::ConstCoeffIter b, std::size_t coeff_count,
         std::vector<Modulus> const& coeff_modulus, util::CoeffIter result) {
#pragma omp parallel for
  for (size_t j = 0; j < coeff_modulus.size(); j++) {
    util::sub_poly_coeffmod(a + (j * coeff_count),
                            b + (j * coeff_count),
                            coeff_count,
                            coeff_modulus[j],
                            result + (j * coeff_count));
  }
}

void copy(util::ConstCoeffIter a, std::size_t coeff_count, std::size_t coeff_modulus_count,
          util::CoeffIter result) {
#pragma omp parallel for
  for (size_t i = 0; i < coeff_modulus_count; i++) {
    util::set_poly(a + (i * coeff_count), coeff_count, 1, result + (i * coeff_count));
  }
}

void to_eval_rep(util::CoeffIter a, size_t coeff_count, size_t coeff_modulus_count, util::NTTTables const* small_ntt_tables) {
#pragma omp parallel for
  for (size_t j = 0; j < coeff_modulus_count; j++) {
    util::ntt_negacyclic_harvey(a + (j * coeff_count), small_ntt_tables[j]); // ntt form
  }
}

void to_coeff_rep(util::CoeffIter a, size_t coeff_count, size_t coeff_modulus_count, util::NTTTables const* small_ntt_tables) {
#pragma omp parallel for
  for (size_t j = 0; j < coeff_modulus_count; j++) {
    util::inverse_ntt_negacyclic_harvey(a + (j * coeff_count), small_ntt_tables[j]); // non-ntt form
  }
}

long double infty_norm(util::ConstCoeffIter a, SEALContext::ContextData const* context_data) {
  auto &ciphertext_parms = context_data->parms();
  auto &coeff_modulus = ciphertext_parms.coeff_modulus();
  size_t coeff_mod_count = coeff_modulus.size();
  size_t coeff_count = ciphertext_parms.poly_modulus_degree();
  auto decryption_modulus = context_data->total_coeff_modulus();
  auto upper_half_threshold = context_data->upper_half_threshold();

  long double max = 0;

  auto aCopy(util::allocate_zero_poly(coeff_count, coeff_mod_count, MemoryManager::GetPool()));
  copy(a, coeff_count, coeff_mod_count, aCopy.get());

  // CRT-compose the polynomial
  context_data->rns_tool()->base_q()->compose_array(aCopy.get(), coeff_count, MemoryManager::GetPool());

  long double two_pow_64 = powl(2.0, 64);

  for (std::size_t i = 0; i < coeff_count; i++) {
    long double coeff = 0.0, cur_pow = 1.0;
    if (util::is_greater_than_or_equal_uint(aCopy.get() + (i * coeff_mod_count),
                                            upper_half_threshold, coeff_mod_count)) {
      for (std::size_t j = 0; j < coeff_mod_count; j++, cur_pow *= two_pow_64) {
        if (aCopy[i * coeff_mod_count + j] > decryption_modulus[j]) {
          auto diff = aCopy[i * coeff_mod_count + j] - decryption_modulus[j];
          coeff += diff ? static_cast<long double>(diff) * cur_pow : 0.0;
        } else {
          auto diff = decryption_modulus[j] - aCopy[i * coeff_mod_count + j];
          coeff -= diff ? static_cast<long double>(diff) * cur_pow : 0.0;
        }
      }
    } else {
      for (std::size_t j = 0; j < coeff_mod_count; j++, cur_pow *= two_pow_64) {
        auto curr_coeff = aCopy[i * coeff_mod_count + j];
        coeff += curr_coeff ? static_cast<long double>(curr_coeff) * cur_pow : 0.0;
      }
    }

    if (fabsl(coeff) > max) {
      max = fabsl(coeff);
    }
  }

  return max;
}

long double l2_norm(util::ConstCoeffIter a, SEALContext::ContextData const* context_data) {
  auto &ciphertext_parms = context_data->parms();
  auto &coeff_modulus = ciphertext_parms.coeff_modulus();
  size_t coeff_mod_count = coeff_modulus.size();
  size_t coeff_count = ciphertext_parms.poly_modulus_degree();
  auto decryption_modulus = context_data->total_coeff_modulus();
  auto upper_half_threshold = context_data->upper_half_threshold();

  long double sum = 0;

  auto aCopy(util::allocate_zero_poly(coeff_count, coeff_mod_count, MemoryManager::GetPool()));
  copy(a, coeff_count, coeff_mod_count, aCopy.get());

  // CRT-compose the polynomial
  context_data->rns_tool()->base_q()->compose_array(aCopy.get(), coeff_count, MemoryManager::GetPool());

  long double two_pow_64 = powl(2.0, 64);

  for (std::size_t i = 0; i < coeff_count; i++) {
    long double coeff = 0.0, cur_pow = 1.0;
    if (util::is_greater_than_or_equal_uint(aCopy.get() + (i * coeff_mod_count),
                                            upper_half_threshold, coeff_mod_count)) {
      for (std::size_t j = 0; j < coeff_mod_count; j++, cur_pow *= two_pow_64) {
        if (aCopy[i * coeff_mod_count + j] > decryption_modulus[j]) {
          auto diff = aCopy[i * coeff_mod_count + j] - decryption_modulus[j];
          coeff += diff ? static_cast<long double>(diff) * cur_pow : 0.0;
        } else {
          auto diff = decryption_modulus[j] - aCopy[i * coeff_mod_count + j];
          coeff -= diff ? static_cast<long double>(diff) * cur_pow : 0.0;
        }
      }
    } else {
      for (std::size_t j = 0; j < coeff_mod_count; j++, cur_pow *= two_pow_64) {
        auto curr_coeff = aCopy[i * coeff_mod_count + j];
        coeff += curr_coeff ? static_cast<long double>(curr_coeff) * cur_pow : 0.0;
      }
    }

    sum += coeff * coeff;
  }

  return sqrtl(sum);
}

std::string poly_to_string(std::uint64_t const* value, EncryptionParameters const& parms) {
  auto coeff_modulus = parms.coeff_modulus();
  size_t coeff_mod_count = coeff_modulus.size();
  size_t coeff_count = parms.poly_modulus_degree();
  std::ostringstream result;
  for (size_t i = 0; i < coeff_mod_count; i++) {
    auto mod = coeff_modulus[i].value();
    if (i>0) {
      result << std::endl;
    }
    result << "[" << mod << "]: ";
    for (size_t j = 0; j < coeff_count; j++) {
      std::uint64_t v = *value;
      if (v >= mod/2) {
        result << "-" << mod-v;
      } else {
        result << v;
      }
      result << (j==coeff_count?"":", ");
      value++;
    }
  }
  return result.str();
}


void print_poly(std::uint64_t const* value, EncryptionParameters const& parms, size_t max_count) {
  auto coeff_modulus = parms.coeff_modulus();
  size_t coeff_mod_count = coeff_modulus.size();
  size_t coeff_count = parms.poly_modulus_degree();
  for (size_t i = 0; i < coeff_mod_count; i++) {
    auto mod = coeff_modulus[i].value();
    std::uint64_t const* v = value + i*coeff_count;
    if (i>0) {
      std::cout << std::endl;
    }
    std::cout << "[" << mod << "]: ";
    for (size_t j = 0; j < coeff_count && (max_count == 0 || j < max_count); j++) {
      if (*v >= mod/2) {
        std::cout << "-" << mod-(*v);
      } else {
        std::cout << *v;
      }
      std::cout << (j==coeff_count?"":", ");
      v++;
    }
  }
  std::cout.flush();
}



void evalPlainAdd(std::vector<cx_double> & res,
                  std::vector<cx_double> const& in0, std::vector<cx_double> const& in1) {
  size_t len = std::min(in0.size(), in1.size());
  res.resize(len);
  for (size_t i = 0; i < len; i++) {
    res[i] = in0[i] + in1[i];
  }
}


void evalPlainMul(std::vector<cx_double> & res,
                  std::vector<cx_double> const& in0, std::vector<cx_double> const& in1) {
  size_t len = std::min(in0.size(), in1.size());
  res.resize(len);
  for (size_t i = 0; i < len; i++) {
    res[i] = in0[i] * in1[i];
  }
}

void evalPlainNegate(std::vector<cx_double> & res, std::vector<cx_double> const& in) {
  size_t len = in.size();
  res.resize(len);
  for (size_t i = 0; i < len; i++) {
    res[i] = -in[i];
  }
}

void evalPlainInverse(std::vector<cx_double> & res, std::vector<cx_double> const& in) {
  size_t len = in.size();
  res.resize(len);
  for (size_t i = 0; i < len; i++) {
    res[i] = 1.0 / in[i];
  }
}

void evalPlainPowerOf2(std::vector<cx_double> & res, std::vector<cx_double> const& in, size_t logDeg) {
  res = in;                    // copy all the numbers
  for (size_t j = 0; j < logDeg; j++) {
    for (size_t i = 0; i < in.size(); i++) {
      res[i] = res[i] * res[i];
    }
  }
}




double largestElm(std::vector<std::complex<double>> const& vec) {
  double m = 0;
  for (auto& x : vec) {
    if (m < std::abs(x.real()))
      m = std::abs(x.real());
    if (m < std::abs(x.imag()))
      m = std::abs(x.imag());
  }
  return m;
}

double maxDiff(std::vector<cx_double> const& in0, std::vector<cx_double> const& in1) {
  size_t len = std::min(in0.size(), in1.size());
  std::vector<cx_double> tmp(len);
  evalPlainNegate(tmp, in1);
  evalPlainAdd(tmp, in0, tmp);
  return largestElm(tmp);
}

double relError(std::vector<cx_double> const& in0, std::vector<cx_double> const& in1) {
  size_t len = std::min(in0.size(), in1.size());
  std::vector<cx_double> diff(len);
  evalPlainNegate(diff, in1);
  evalPlainAdd(diff, diff, in0);
  double res = 0;
  for (size_t i = 0; i < len; i++) {
    double tmp = std::fabs(diff[i].real() / in1[i].real());
    if (res < tmp) {
      res = tmp;
    }
    tmp = std::fabs(diff[i].imag() / in1[i].imag());
    if (res < tmp) {
      res = tmp;
    }
  }
  return res;
}

void randomComplexVector(std::vector<cx_double>& array, size_t n, double rad) {
  if (rad <= 0) {
    rad = 1.0;                // default radius = 1
  }
  array.resize(n);             // allocate space
  for (auto& x : array) {
    long bits = std::rand();         // 32 random bits
    double r = std::sqrt(bits & 0xffff) / 256.0; // sqrt(uniform[0,1])
    double theta =
        2.0L * M_PI * ((bits >> 16) & 0xffff) / 65536.0; // uniform(0,2pi)
    x = std::polar(rad * r, theta);
  }
}

cx_double * randomComplexVector(size_t n, double rad) {
  std::vector<cx_double> vec(n);
  cx_double * pvec = new cx_double[n];
  randomComplexVector(vec, n, rad);
  for (size_t i = 0; i < n; i++) {
    pvec[i] = vec[i];
  }
  return pvec;
}

void randomRealVector(std::vector<cx_double>& array, size_t n, double B) {
  B = fabs(B);
  array.resize(n);             // allocate space
  for (auto& x : array) {
    long bits = std::rand();         // 32 random bits
    double r = std::sqrt(bits & 0xffff) / 256.0; // sqrt(uniform[0,1])
    double sign = ((bits >> 16) & 0xffff) > 32767 ? 1.0 : -1.0;
    x.real(B * r * sign);
    x.imag(0);
  }
}
cx_double * randomRealVector(size_t n, double rad) {
  std::vector<cx_double> vec(n);
  cx_double * pvec = new cx_double[n];
  randomRealVector(vec, n, rad);
  for (size_t i = 0; i < n; i++) {
    pvec[i] = vec[i];
  }
  return pvec;
}


void copyTo(std::complex<double> * dst, std::complex<double> const* src, size_t len) {
  for (size_t i = 0; i < len; i++) {
    dst[i] = src[i];
  }
}

bool isEqual(std::complex<double> const* m0, std::complex<double> const* m1, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (m0[i] != m1[i]) {
      std::cout.precision(10);
      std::cout << "different @ " << i << " : "
                << std::scientific << m0[i] << ", " << m1[i] << std::endl;
      return false;
    }
  }
  return true;
}