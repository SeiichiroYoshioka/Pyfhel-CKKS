"""
Applied Cryptography - FHE Lab
========================================

The present demo displays the use of Pyfhel-CKKS for the FHE lab
"""
# Local module
from Pyfhel import PyCtxt, Pyfhel, PyPtxt


# Pyfhel class contains most of the functions.
# PyPtxt is the plaintext class
# PyCtxt is the ciphertext class

# ================================ MODULE 2 =====================================
def module2():
    print("\n\n MODULE 2:")
    print("1. Creating Context and encrypt 0")
    HE = Pyfhel()  # Creating empty Pyfhel object

    n = 32768
    log_scale = 40

    # Fancy way of automatically setting the q_i's instead of providing a manual list
    maxQBits = HE.maxBitCount(n, 256)
    qs = [60]  # Set the first prime to be 60-bit
    totalQBits = 60
    while (totalQBits <= maxQBits - 60):  # reserve the last special prime (60-bit)
        qs.append(log_scale)  # add a prime modulus of size == scaleBits
        totalQBits += log_scale
    qs.append(60)  # add the special prime modulus

    # Setup context and generate keys
    HE.contextGen(n=n, qs=qs)
    HE.keyGen()  # Key Generation.

    # Encode into a Polynomial
    ptxt_input = HE.encode(0, scale=2 ** log_scale)

    # Encrypt the plaintext
    ctxt_input = HE.encrypt(ptxt_input)

    # Not doing any computation
    ctxt_res = ctxt_input

    # decrypt again
    ptxt_res = HE.decrypt(ctxt_res)

    # decode into a vector of complex
    val_res = HE.decodeComplex(ptxt_res)

    # // Decryption
    # Plaintext ptxt_res;
    # decryptor.decrypt(ctxt_res, ptxt_res); // approx decryption
    #
    # // Decode the plaintext polynomial
    # std::vector<std::complex<double>> val_res;
    # encoder.decode(ptxt_res, val_res);    // decode to an array of complex
    #
    # // Check computation errors
    # std::vector<std::complex<double>> pt_res(slot_count);
    # pt_res = val_input; // Since we performed no homomorphic computation
    # std::cout << "computation error = " << maxDiff(pt_res, val_res)
    #           << ", relative error = " << relError(pt_res, val_res) << std::endl;
    #
    # // **************************************************
    # // Key recovery attack
    # // **************************************************
    #
    # // First we encode the decrypted floating point numbers back into polynomials
    # Plaintext ptxt_enc;
    # encoder.encode(val_res, ctxt_res.parms_id(), ctxt_res.scale(), ptxt_enc);
    #
    # // Then we get some useful parameters used in the scheme
    # auto context_data = context.get_context_data(ctxt_res.parms_id());
    # auto small_ntt_tables = context_data->small_ntt_tables();
    # auto &ciphertext_parms = context_data->parms();
    # auto &coeff_modulus = ciphertext_parms.coeff_modulus();
    # size_t coeff_mod_count = coeff_modulus.size();
    # size_t coeff_count = ciphertext_parms.poly_modulus_degree();
    #
    # // Check encoding error
    # Plaintext ptxt_diff;
    # ptxt_diff.parms_id() = parms_id_zero;
    # ptxt_diff.resize(util::mul_safe(coeff_count, coeff_modulus.size()));
    # sub(ptxt_enc.data(), ptxt_res.data(), coeff_count, coeff_modulus, ptxt_diff.data());
    # to_coeff_rep(ptxt_diff.data(), coeff_count, coeff_mod_count, small_ntt_tables);
    # long double err_norm = infty_norm(ptxt_diff.data(), context_data.get());
    # std::cout << "encoding error = " << err_norm << std::endl;
    #
    # std::cout << "key recovery ..." << std::endl;
    # MemoryPoolHandle pool = MemoryManager::GetPool();
    # // rhs = ptxt_enc - ciphertext.b
    # seal::util::Pointer<unsigned long, void> rhs = util::allocate_zero_poly(poly_modulus_degree, coeff_mod_count, pool);
    # sub(ptxt_enc.data(), ctxt_res.data(0), coeff_count, coeff_modulus, rhs.get());
    #
    # auto ca =  util::allocate_zero_poly(poly_modulus_degree, coeff_mod_count, pool);
    # copy(ctxt_res.data(1), coeff_count, coeff_modulus.size(), ca.get());
    #
    # std::cout << "compute ca^{-1} ..." << std::endl;
    # auto ca_inv = util::allocate_zero_poly(poly_modulus_degree, coeff_mod_count, pool);
    #
    # bool has_inv = inverse(ca.get(), coeff_count, coeff_modulus, ca_inv.get());
    # if (!has_inv) {
    #   throw std::logic_error("ciphertext[1] has no inverse");
    # }
    #
    # // The recovered secret: key_guess = ciphertext.a^{-1} * rhs
    # std::cout << "compute (m' - cb) * ca^{-1} ..." << std::endl;
    # auto key_guess = util::allocate_zero_poly(poly_modulus_degree, coeff_mod_count, pool);
    # multiply(rhs.get(), ca_inv.get(), coeff_count, coeff_modulus, key_guess.get());
    #
    # bool is_found = util::is_equal_uint(key_guess.get(),
    #                                     secret_key.data().data(),
    #                                     coeff_count*coeff_mod_count);
    #
    # // In retrospect, let's see how big the re-encoded polynomial is
    # to_coeff_rep(ptxt_enc.data(), coeff_count, coeff_mod_count, small_ntt_tables);
    # std::cout << "m' norm bits = " << log2(l2_norm(ptxt_enc.data(), context_data.get())) << std::endl;
    #
    # return is_found;


# ================================ MODULE 1 =====================================
def module1():
    print("\n\n MODULE 1:")
    print("1. Creating Context and KeyGen in a Pyfhel Object.")
    HE = Pyfhel()  # Creating empty Pyfhel object
    n = 16834
    qs = [30, 30, 30, 30, 30]
    HE.contextGen(n=16384, qs=qs)
    HE.keyGen()  # Key Generation.

    print("2. Encrypting the input numbers")
    x = 3.1
    y = 4.1
    z = 5.9

    ptxt_x = HE.encode(x, scale=2 ** 30)
    ptxt_y = HE.encode(y, scale=2 ** 30)
    ptxt_z = HE.encode(z, scale=2 ** 30)

    # Testing: Decode immediately
    print("\tx=" + str(HE.decode(ptxt_x)[0]) + ", y=" + str(HE.decode(ptxt_y)[0]) + ", z=" + str(HE.decode(ptxt_z)[0]))

    ctxt_x = HE.encrypt(ptxt_x)
    ctxt_y = HE.encrypt(ptxt_y)
    ctxt_z = HE.encrypt(ptxt_z)

    # Testing: Decrypt immediately
    print(
        "\tx=" + str(HE.decode(HE.decrypt(ctxt_x))[0]) + ", y=" + str(HE.decode(HE.decrypt(ctxt_y))[0]) + ", z=" + str(
            HE.decode(HE.decrypt(ctxt_z))[0]))

    print("3. Compute x+y")
    ctxtSum = ctxt_x + ctxt_y
    print("\tx+y=" + str(HE.decode(HE.decrypt(ctxtSum))[0]))

    print("4. Compute z*5:")
    # Instead of doing this:
    # ptxt_five = HE.encode(5, scale=2**30)
    # ctxtProd = ctxt_z * ptxt_five
    # We can be more concise in Pyfhel:
    ctxtProd = ctxt_z * 5
    print("\tz*5=" + str(HE.decode(HE.decrypt(ctxtProd))[0]))

    print("5. Multiply (x+y) * (z*5):")
    ctxt_t = ctxtSum * ctxtProd
    print("\t(x+y)*(z*5)=" + str(HE.decode(HE.decrypt(ctxt_t))[0]))

    print("6. Try to add 10")
    try:
        ptxt_ten = HE.encode(10, scale=2 ** 30)
        ctxt_result = ctxt_t + ptxt_ten
    except ValueError:
        print("\tFirst attempt at adding failed because of scale mismatch")

    ptxt_ten = HE.encode(10, scale=2 ** 90)
    ctxt_result = ctxt_t + ptxt_ten

    # Note that the simple version will also works
    # That's because it encodes the ptxt with the scale of the ctxt
    # ctxt_result = ctxt_t + 10

    print("\t((x+y)*(z*5))+10=" + str(HE.decode(HE.decrypt(ctxt_result))[0]))


# ================================ MODULE 3 =====================================
def module3():
    print("\n\n MODULE 3:")
    print("0. Generate Keys (including relin keys for later)")
    HE = Pyfhel()  # Creating empty Pyfhel object
    n = 16834
    qs = [30, 30, 30, 30, 30]
    HE.contextGen(n=16384, qs=qs)
    HE.keyGen()  # Key Generation
    HE.relinKeyGen()  # Generate Relinerization Keys

    print("1. Compute ((x+y)*(z*5)) as before ")

    x = 3.1
    y = 4.1
    z = 5.9

    ptxt_x = HE.encode(x, scale=2 ** 30)
    ptxt_y = HE.encode(y, scale=2 ** 30)
    ptxt_z = HE.encode(z, scale=2 ** 30)

    # Testing: Decode immediately
    print("\tx=" + str(HE.decode(ptxt_x)[0]) + ", y=" + str(HE.decode(ptxt_y)[0]) + ", z=" + str(HE.decode(ptxt_z)[0]))

    ctxt_x = HE.encrypt(ptxt_x)
    ctxt_y = HE.encrypt(ptxt_y)
    ctxt_z = HE.encrypt(ptxt_z)

    # Testing: Decrypt immediately
    print(
        "\tx=" + str(HE.decode(HE.decrypt(ctxt_x))[0]) + ", y=" + str(HE.decode(HE.decrypt(ctxt_y))[0]) + ", z=" + str(
            HE.decode(HE.decrypt(ctxt_z))[0]))

    ctxtSum = ctxt_x + ctxt_y
    print("\tx+y=" + str(HE.decode(HE.decrypt(ctxtSum))[0]))

    # Instead of doing this:
    # ptxt_five = HE.encode(5, scale=2**30)
    # ctxtProd = ctxt_z * ptxt_five
    # We can be more concise in Pyfhel:
    ctxtProd = ctxt_z * 5
    print("\tz*5=" + str(HE.decode(HE.decrypt(ctxtProd))[0]))

    ctxt_t = ctxtSum * ctxtProd
    print("\t(x+y)*(z*5)=" + str(HE.decode(HE.decrypt(ctxt_t))[0]))

    print("2. Encode and encrypt 10")
    ptxt_d = HE.encode(10, 2 ** 30)
    ctxt_d = HE.encrypt(ptxt_d)
    print("\td=" + str(HE.decode(HE.decrypt(ctxt_d))[0]))

    print("3. Try to add ctxt_t and ctxt_d")
    try:
        ctxt_result = ctxt_t + ctxt_d
    except ValueError:
        print("\tFirst attempt at adding failed because of scale mismatch")

    print("4. Rescale ctxt_t and try again")
    HE.rescale_to_next(ctxt_t)  # 2^90 -> 2^60
    HE.rescale_to_next(ctxt_t)  # 2^60 -> 2^30

    try:
        ctxt_result = ctxt_t + ctxt_d
    except ValueError:
        print("\tSecond attempt at adding failed because moduli mismatch")

    print("5. Modswitch ctxt_d down and try again")
    HE.mod_switch_to_next(ctxt_d)
    HE.mod_switch_to_next(ctxt_d)  # twice, to match the two rescales

    try:
        ctxt_result = ctxt_t + ctxt_d
    except ValueError:
        print("\tThird attempt at adding failed because scales still mismatch slightly!")

    print("5. Override ctxt_t scale and try again")
    ctxt_t.set_scale(2 ** 30)
    ctxt_result = ctxt_t + ctxt_d
    print("\t((x+y)*(z*5))+10=" + str(HE.decode(HE.decrypt(ctxt_result))[0]))

    print("9. Encrypt 5 into ctxt_v  ")
    ptxt_v = HE.encode(5, scale=2 ** 30)
    ctxt_v = HE.encrypt(ptxt_v)

    print("\tv=" + str(HE.decode(HE.decrypt(ctxt_v))[0]))

    print("10. ctxt-ctxt product between ctxt_z and ctxt_v")
    ctxtProd = ctxt_z * ctxt_v
    print("\t(z*v)=" + str(HE.decode(HE.decrypt(ctxtProd))[0]))

    print("10. Relinearize")
    HE.relinearize(ctxtProd)

    print("12. Rest of the computation remains the same")
    ctxt_t = ctxtSum * ctxtProd
    HE.rescale_to_next(ctxt_t)  # 2^90 -> 2^60
    HE.rescale_to_next(ctxt_t)  # 2^60 -> 2^30
    # ctxt_d is still modswitched from above, since it wasn't overwritten
    ctxt_t.set_scale(2 ** 30)
    ctxt_result = ctxt_t + ctxt_d
    print("\t((x+y)*(z*5))+10=" + str(HE.decode(HE.decrypt(ctxt_result))[0]))


# module1()
module2()
# module3()
