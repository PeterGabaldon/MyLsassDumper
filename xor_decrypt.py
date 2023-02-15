#! /usr/bin/python3

from itertools import cycle

def xore(data, key):
    return bytes(a ^ b for a, b in zip(data, cycle(key)))

def xor_decrypt():
	f_path = "C:\\Users\\Peter\\Desktop\\sorpresa.txt"
	xor_key = b"abc1234"

	with open(f_path, "rb") as f, open(f_path+"_decrypted", "wb") as f_decrypted:
		f_decrypted.write(xore(f.read(), xor_key))

if __name__ == "__main__":
	xor_decrypt();
