import itertools

# KEMs with NIST security level 1
l1_kem = {
	"FRODOKEM640SHAKE",
	"SIKE434",
	"LIGHTSABER",
	"HQCRMRS128",
	"KYBER512",
	"NTRUHPS2048509",
	"MCELIECE348864",
	#"MCELIECE348864F"
}

# Signatures with NIST security level 1
l1_sig = {
	"DILITHIUM2",
	"FALCON512",
	"RAINBOWICLASSIC",
# one sphincs is just enough for now
	#"sphincs_shake256_128f_robust",
	"SPHINCSSHAKE256128FSIMPLE",
	"SPHINCSSHA256128FSIMPLE"
	#"sphincs_shake256_128s_robust",
	#"sphincs_shake256_128s_simple",
}

# KEMs with NIST security level 3
l3_kem = {
	"FRODOKEM976SHAKE",
	"SABER",
	"HQCRMRS192",
	"KYBER768",
	"NTRUHPS2048677",
	"NTRUHRSS701",
	"MCELIECE460896",
	#"MCELIECE460896F"
}

# Signatures with NIST security level 3
l3_sig = {
	"DILITHIUM3",
	"RAINBOWIIICLASSIC",
	#"sphincs_shake256_192f_robust",
	"SPHINCSSHAKE256192FSIMPLE",
	"SPHINCSSHA256192FSIMPLE"
	#"sphincs_shake256_192s_robust",
	#"sphincs_shake256_192s_simple"
}

# KEMs with NIST security level 5
l5_kem = {
	"FRODOKEM1344SHAKE",
	"FIRESABER",
	"HQCRMRS256",
	"KYBER1024",
	"NTRUHPS4096821",
	"MCELIECE6688128",
	#"MCELIECE6688128F",
	#"MCELIECE6960119",
	#"MCELIECE6960119F",
	#"MCELIECE8192128",
	#"MCELIECE8192128F"
}

# Signatures with NIST security level 5
l5_sig = {
	"DILITHIUM5",
	"FALCON1024",
	"RAINBOWVCLASSIC",
	#"sphincs_shake256_256f_robust",
	"SPHINCSSHAKE256256FSIMPLE",
	"SPHINCSSHA256256FSIMPLE",
	#"sphincs_shake256_256s_robust",
	#"sphincs_shake256_256s_simple",
}

def format_line(item, lvl):
	return ["\tREG_ALG("+item[0]+", "+item[1]+", "+str(lvl)+"),"]

def print_matrix_for_sec_level(kem, sig, lvl):
	lines = []
	for item in itertools.product(kem, sig):
		lines += format_line(item, lvl)
	return lines

def print_schemes_variable():

	lines = print_matrix_for_sec_level(l1_sig, l1_kem, 1)
	lines += print_matrix_for_sec_level(l3_sig, l3_kem, 3)
	lines += print_matrix_for_sec_level(l5_sig, l5_kem, 5)

	print("const params_t algs["+str(len(lines))+"] = {")
	for line in lines:
		print(line)
	print("};\n")

print_schemes_variable()