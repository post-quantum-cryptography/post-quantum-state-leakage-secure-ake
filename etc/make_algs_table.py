import itertools

# KEMs with NIST security level 1
l1_kem = {
	"bike1_l1_fo",
	"classic_mceliece_348864f",
	"frodokem_640_shake",
	"sike_p434",
	"sike_p434_compressed",
	"saber_lightsaber",
	"hqc_128_1_cca2",
	"kyber_512",
	"ntru_hps2048509",
}

# Signatures with NIST security level 1
l1_sig = {
	"dilithium_2",
	"falcon_512",
	"picnic3_L1",
	"rainbow_Ia_classic",
# one sphincs is just enough for now
	#"sphincs_shake256_128f_robust",
	"sphincs_shake256_128f_simple",
	#"sphincs_shake256_128s_robust",
	#"sphincs_shake256_128s_simple",
}

# KEMs with NIST security level 3
l3_kem = {
	"bike1_l3_fo",
	"classic_mceliece_460896f",
	"frodokem_976_shake",
	"sike_p610",
	"sike_p610_compressed",
	"saber_saber",
	"hqc_192_1_cca2",
	"kyber_768",
	"ntru_hps2048677",
	"ntru_hrss701",
}

# Signatures with NIST security level 3
l3_sig = {
	"dilithium_4",
	"picnic3_L3",
	"rainbow_IIIc_classic",
	#"sphincs_shake256_192f_robust",
	"sphincs_shake256_192f_simple",
	#"sphincs_shake256_192s_robust",
	#"sphincs_shake256_192s_simple"
}

# KEMs with NIST security level 5
l5_kem = {
	"classic_mceliece_6688128f",
	"classic_mceliece_6960119f",
	"classic_mceliece_8192128f",
	"frodokem_1344_shake",
	"sike_p751",
	"sike_p751_compressed",
	"saber_firesaber",
	"hqc_256_1_cca2",
	"hqc_256_3_cca2",
	"kyber_1024",
	"ntru_hps4096821",
}

# Signatures with NIST security level 5
l5_sig = {
	"falcon_1024",
	"picnic3_L5",
	"rainbow_Vc_classic",
	#"sphincs_shake256_256f_robust",
	"sphincs_shake256_256f_simple",
	#"sphincs_shake256_256s_robust",
	#"sphincs_shake256_256s_simple",
}

def format_line(item):
	return ["\tREG_ALGS("+item[0]+", "+item[1]+"),"]

def print_matrix_for_sec_level(kem, sig):
	lines = []
	for item in itertools.product(kem, sig):
		lines += format_line(item)
	return lines

def print_schemes_variable():

	lines = print_matrix_for_sec_level(l1_sig, l1_kem)
	lines += print_matrix_for_sec_level(l3_sig, l3_kem)
	lines += print_matrix_for_sec_level(l5_sig, l5_kem)

	print("const params_t algs["+str(len(lines))+"] = {")
	for line in lines:
		print(line)
	print("};\n")

print_schemes_variable()