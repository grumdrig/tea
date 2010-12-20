#!/usr/bin/python
"""
Tiny Encryption Algorithm (TEA) implementation
----------------------------------------------

The encrypt/decrypt functions do just that for a single block (2
4-byte unsigned integers).

The encipher/decipher functions act on a string, breaking it into
blocks and encrypt-/decrypting.

All functions take a key parameter which is expected to be 4 unsigned
4-byte integers.

CAVEAT: Encipher right-pads with zero bytes which are stripped off in
decipher, so a message ending in zero bytes will become garbled.
Corollary: there's an assumption that these functions will be used to
encipher plain, readable text.

See http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm for reference
"""

import struct

DELTA = 0x9e3779b9  # key schedule constant

# Helper for unsigned long math
def ul(v):
  return v & 0xFFFFFFFF


def encrypt(v0, v1, key, rounds=32):
  assert len(key) == 4
  sum = 0
  for i in range(rounds):
    v0 = ul(v0 + ((v1 << 4 ^ v1 >> 5) + v1 ^ sum + key[sum & 3]))
    sum = ul(sum + DELTA)
    v1 = ul(v1 + ((v0 << 4 ^ v0 >> 5) + v0 ^ sum + key[sum>>11 & 3]))
  return v0, v1


def decrypt(v0, v1, key, rounds=32):
  assert len(key) == 4
  sum = ul(DELTA * rounds)
  for i in range(rounds):
    v1 = ul(v1 - ((v0 << 4 ^ v0 >> 5) + v0 ^ sum + key[sum>>11 & 3]))
    sum = ul(sum - DELTA)
    v0 = ul(v0 - ((v1 << 4 ^ v1 >> 5) + v1 ^ sum + key[sum & 3]))
  return v0, v1


def encipher(s, key):
  """TEA-encipher a string"""
  assert struct.calcsize('I') == 4
  s = s.ljust(8 * int((len(s) + 7)/8), '\x00')  # pad with 0's
  u = struct.unpack('%dI' % (len(s) / 4), s)
  e = [encrypt(u[i],u[i+1], key) for i in range(len(u))[::2]]
  return ''.join([struct.pack('2I', ee,ef) for ee,ef in e])
    

def decipher_raw(s, key):
  """TEA-decipher a raw string"""
  assert struct.calcsize('I') == 4
  assert len(s) % 8 == 0, len(s)
  u = struct.unpack('%dI' % (len(s) / 4), s)
  e = [decrypt(u[i],u[i+1], key) for i in range(len(u))[::2]]
  return ''.join([struct.pack('2I', ee,ef) for ee,ef in e])

def decipher(s, key):
  """TEA-decipher a readable string"""
  return decipher_raw(s, key).rstrip('\x00')


def main():
  """Usage: tea.py [OPTS] [KEY] [INFILE [OUTFILE]]
OPTS:
  -d       Decipher (default is to encipher)
  -h       Ciphertext is expressed in hex format (default for a tty)
  -t       Ciphertext is expressed as literal text (default otherwise)
KEY:
  -k KEY      A hexadecimal key string of length exactly 16
  -p PASSWORD Password is used to generate an md5 hash, which is used as key
  -f KEYFILE  A key file of length exactly 16
  If no key, keyfile or password is provided, a password is read from stdin.
  This requires that INFILE be specified.
INFILE
  Path to file containing plain or cipher text
OUTFILE
  Path to file to write
If either FILE argument is omitted, stdin/stdout is used."""
  def usage(msg=None):
    if msg: print >>sys.stderr, 'Error:', msg
    print >>sys.stderr, main.__doc__
    sys.exit(-1)
  cipher = encipher
  hex = None
  key = None
  password = None
  import sys, getopt
  opts,args = getopt.getopt(sys.argv[1:], "dhp:tk:")
  for o,a in opts:
    if o == '-d':
      cipher = decipher
    elif o == '-h':
      hex = True
    elif o == '-t':
      hex = False
    elif o == '-p':
      password = a
    elif o == '-k':
      key = a
    elif o == '-f':
      key = open(a, 'rb').read()
    else:
      usage()
      if (len(args) < 1) or (len(args[0]) != 16):
        usage
  if not (key or password or args): usage()
  if not key:
    import getpass, hashlib
    if not password:
      password = getpass.getpass("Password:")
    key = hashlib.md5(password).digest()[:16]
  if len(key) != 16:
    usage('key length must be 16')
  key = struct.unpack('4I', key)

  input = args and open(args.pop(0), 'rb') or sys.stdin
  output = args and open(args.pop(0), 'wb') or sys.stdout

  message = input.read()
  if (cipher == decipher) and ((hex == True) or
                               ((hex == None) and input.isatty())):
    message = message.decode('hex')
  result = cipher(message, key)
  if (cipher == encipher) and ((hex == True) or
                               ((hex == None) and output.isatty())):
    result = result.encode('hex')
  output.write(result)


if __name__ == "__main__":
  main()
  
