class Pailier:
    '''Pailier class contains key generation (and additional functions and classes for it), text sign and verification. Additionally it contains arithmetic functions to be used with encrypted text'''
    class PrivateKey:
        '''Class to generate and store private key'''
        def __init__(self, p, q, n):
            '''Calculates the simple versions of lambda and mu if p and q has equivalent length '''
            self.l = (p-1) * (q-1)
            self.m = inverse_mod(self.l, n)

        def __repr__(self):
            '''The representative output of the class'''
            return '<PrivateKey: %s %s>' % (self.l, self.m)

    class PublicKey(object):
        '''Class to generate and store public key'''
        def __init__(self, n):
            '''Calculates n and g if o and q has equivalent lenght'''
            self.n = n
            self.n_sq = n * n
            self.g = n + 1

        def __repr__(self):
            '''The representative output of the class'''
            return '<PublicKey: %s>' % self.n

    def __rdp(self, nbits):
        '''Generates random prime of nbits length. The length of at least 512 bits is recommended'''
        while True:
            p = random_prime(2^nbits-1, false, 2^(nbits-1))
            if ZZ((p+1)/2).is_prime():
                return p

    def generate_keypair(self, bits):
        '''Generates private and public keys'''
        p = self.__rdp(bits/2)
        q = self.__rdp(bits/2)
        # Compute n
        n = p * q
        return self.PrivateKey(p, q, n), self.PublicKey(n)

    def encrypt(self, public_key, message):
        '''Encrypts the message where 0 <= m < n'''
        while True:
            # Select random r where 0 < r < n
            r = self.__rdp(int(round(log(public_key.n, 2))))
            if r > 0 and r < public_key.n:
                break
        x = pow(r, public_key.n, public_key.n_sq)
        # Compute ciphertext
        ciphertext = (pow(public_key.g, message, public_key.n_sq) * x) % public_key.n_sq
        return ciphertext

    def decrypt(self, private_key, public_key, ciphertext):
        '''Decrypts the message'''
        x = pow(ciphertext, private_key.l, public_key.n_sq) - 1
        # As the original paper points out, decryption is "essentially one exponentiation modulo n^2."
        plaintext = (ZZ(x) // public_key.n) * private_key.m % public_key.n
        return plaintext

    def e_add(self, public_key, a, b):
        '''Homomorphic addition of plaintexts'''
        # The product of two ciphertexts will decrypt to the sum of their corresponding plaintexts
        return a * b % public_key.n_sq

    def e_add_const(self, public_key, a, n):
        '''Homomorphic addition of plaintexts'''
        # The product of a ciphertext with a plaintext raising g will decrypt to the sum of the corresponding plaintexts
        return a * power_mod(public_key.g, n, public_key.n_sq) % public_key.n_sq

    def e_mul_const(self, public_key, a, n):
        '''Homomorphic multiplication of plaintexts'''
        # An encrypted plaintext raised to a constant k will decrypt to the product of the plaintext and the constant
        return power_mod(a, n, public_key.n_sq)

# main

p = Pailier()

private_key, public_key = p.generate_keypair(bits = 64)
print("Keys are generated")

# Examples start here. Keys must be generated before.

import random

for i in range(5):
    x = random.randrange(100)
    y = random.randrange(100)
    cx = p.encrypt(public_key, x)
    cy = p.encrypt(public_key, y)
    cz = p.e_add(public_key, cx, cy)
    z = p.decrypt(private_key, public_key, cz)

    print(x, ' + ', y, ' = ', z)
    assert z == x+y

    c1 = random.randrange(15)
    k = p.decrypt(private_key, public_key, (p.e_mul_const(public_key, cz, c1)))
    print(z, ' * ', c1, ' = ', k)
    assert z*c1 == k

    c2 = random.randrange(50)
    l = p.decrypt(private_key, public_key, p.e_mul_const(public_key, p.e_add_const(public_key, cz, c2), c1))
    print(c1, ' * (', z, ' + ', c2, ') = ', l)
    assert c1*(z+c2) == l

    print('------------------------------')
