from __future__ import print_function
import ctypes
import hashlib
import sys, base64, textwrap
import jks


def print_pem(der_bytes, type):
  print("-----BEGIN %s-----" % type)
  print("\r\n".join(
      textwrap.wrap(base64.b64encode(der_bytes).decode('ascii'), 64)))
  print("-----END %s-----" % type)


ks: jks.BksKeyStore = jks.BksKeyStore.load(sys.argv[1], sys.argv[2])
# if any of the keys in the store use a password that is not the same as the store password:
# ks.entries["key1"].decrypt("key_password")

for alias, pk in ks.entries.items():
  print("Private key: %s" % pk.alias)
  print_pem(pk.encrypted, "PRIVATE KEY")
  # if pk.algorithm_oid == jks.util.RSA_ENCRYPTION_OID:
  #   print_pem(pk.pkey, "RSA PRIVATE KEY")
  # else:

  for c in pk.cert_chain:
    print_pem(c.cert, "CERTIFICATE")
  print()

sys.exit(0)


def derive_key(hashfn, purpose_byte, password_str, salt, iteration_count,
               desired_key_size):
  """
    Implements PKCS#12 key derivation as specified in RFC 7292, Appendix B, "Deriving Keys and IVs from Passwords and Salt".
    Ported from BC's implementation in org.bouncycastle.crypto.generators.PKCS12ParametersGenerator.
    hashfn:            hash function to use (expected to support the hashlib interface and attributes)
    password_str:      text string (not yet transformed into bytes)
    salt:              byte sequence
    purpose:           "purpose byte", signifies the purpose of the generated pseudorandom key material
    desired_key_size:  desired amount of bytes of key material to generate
    """
  password_bytes = (password_str.encode('utf-16be') +
                    b"\x00\x00") if len(password_str) > 0 else b""
  u = hashfn().digest_size  # in bytes
  v = hashfn().block_size  # in bytes

  _salt = bytearray(salt)
  _password_bytes = bytearray(password_bytes)

  D = bytearray([purpose_byte]) * v
  S_len = ((len(_salt) + v - 1) // v) * v
  S = bytearray([_salt[n % len(_salt)] for n in range(S_len)])
  P_len = ((len(_password_bytes) + v - 1) // v) * v
  P = bytearray(
      [_password_bytes[n % len(_password_bytes)] for n in range(P_len)])

  I = S + P
  c = (desired_key_size + u - 1) // u
  derived_key = b""

  for i in range(1, c + 1):
    A = hashfn(bytes(D + I)).digest()
    for j in range(iteration_count - 1):
      A = hashfn(A).digest()

    A = bytearray(A)
    B = bytearray([A[n % len(A)] for n in range(v)])

    # Treating I as a concatenation I_0, I_1, ..., I_(k-1) of v-bit
    # blocks, where k=ceiling(s/v)+ceiling(p/v), modify I by
    # setting I_j=(I_j+B+1) mod 2^v for each j.
    for j in range(len(I) // v):
      _adjust(I, j * v, B)

    derived_key += bytes(A)

  # truncate derived_key to the desired size
  derived_key = derived_key[:desired_key_size]
  return derived_key


def _adjust(a, a_offset, b):
  """
    a = bytearray
    a_offset = int
    b = bytearray
    """
  x = (b[-1] & 0xFF) + (a[a_offset + len(b) - 1] & 0xFF) + 1
  a[a_offset + len(b) - 1] = ctypes.c_ubyte(x).value
  x >>= 8

  for i in range(len(b) - 2, -1, -1):
    x += (b[i] & 0xFF) + (a[a_offset + i] & 0xFF)
    a[a_offset + i] = ctypes.c_ubyte(x).value
    x >>= 8


print([
    u for u in derive_key(
        hashlib.sha1,
        3,
        "SwitchBeePrivate",
        [
            93, 134, 207, 244, 205, 79, 213, 134, 152, 5, 112, 148, 135, 93,
            240, 101, 233, 195, 184, 42
        ],
        1026,
        20,
    )
])

# for alias, c in ks.certs.items():
#   print("Certificate: %s" % c.alias)
#   print_pem(c.cert, "CERTIFICATE")
#   print()
#
# for alias, sk in ks.secret_keys.items():
#   print("Secret key: %s" % sk.alias)
#   print("  Algorithm: %s" % sk.algorithm)
#   print("  Key size: %d bits" % sk.key_size)
#   print("  Key: %s" % "".join("{:02x}".format(b) for b in bytearray(sk.key)))
