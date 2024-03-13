import random
import threading
from random import getrandbits, randint
from math import log2


# Greatest Common Divisor
def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b


def mod_inverse(x, n):  # (x * x_inv) % n == 1
    original_n = n
    x1, x2 = 0, 1
    while x > 1:
        q = x // n
        x, n = n, x % n
        x1, x2 = x2 - q * x1, x1
    if x2 < 0:
        x2 += original_n
    return x2


def probin(bit):  # bit: how many bits wants to be generate
    # randomly generate bid odd number
    list = []
    list.append('1')
    for i in range(bit - 2):
        c = random.choice(['0', '1'])
        list.append(c)
    list.append('1')
    res = int(''.join(list), 2)
    return res


def pow_mod(p, q, n):  # p^q mod n, p:Base, q:Exponent, n:Modulus
    # Montgomery Reduction
    res = 1
    while q:
        if q & 1:
            res = (res * p) % n
        q >>= 1
        p = (p * p) % n
    return res


def prime_miller_rabin(a, n):  # n: number needed to be test  a: random.randint(2, n - 1)
    if n < 2:
        return False
    # Test with prime number less than 100
    prime_num_100 = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41
                     , 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97)

    for prime in prime_num_100:
        if n == prime:
            return True
        elif n % prime == 0:
            return False

    # Use miller rabin method to test whether the genertated number is prime number
    if pow_mod(a, n - 1, n) == 1:  # Check if n is a composite number
        d = n - 1
        q = 0
        while not (d & 1):  # Find the odd part of d
            q += 1
            d >>= 1
        m = d

        for i in range(q):
            u = m << i  # Use bit shift for efficiency instead of multiplication
            tmp = pow_mod(a, u, n)
            if tmp in (1, n - 1):
                return True  # n passes the test, might be a prime
        return False  # n fails the test, it's a composite
    else:
        return False


def prime_test(n, k):
    while k > 0:
        a = random.randint(2, n - 1)
        if not prime_miller_rabin(a, n):
            return False
        k = k - 1
    return True


# 产生一个大素数(bit位)
def get_prime(bit):
    """Generate a large prime number of the specified bit length."""
    while True:
        prime_candidate = probin(bit)
        # Attempt to verify if the prime candidate is indeed a prime
        for _ in range(
                50):  # If no prime is found within 50 odd numbers around the pseudo prime, generate a new pseudo prime
            if prime_test(prime_candidate, 5):
                return prime_candidate
            prime_candidate += 2  # Move to the next odd number


def gen_keys(bit):
    p = get_prime(bit)  # Key p
    q = get_prime(bit)  # Key q
    n = p * q  # Public n
    phi_n = (p - 1) * (q - 1)  # Euler's totient function
    # Choose a suitable e, e must be coprime with phi_n
    e = 65537
    while gcd(e, phi_n) != 1:
        e -= 1  # Adjust e if not coprime (though 65537 is usually fine)
    d = mod_inverse(e, phi_n)  # Compute d, the modular inverse of e
    return (n, e), (n, e, d, p, q)
    # public_key = f"PublicKey{(n, e)}"
    # private_key = f"PrivateKey{(n, e, d, p, q)}"
    # return public_key, private_key, d, n


def is_prime(a, b):
    d = gcd(a, b)
    return d == 1


def extended_gcd(a: int, b: int):
    """
    Returns a tuple (r, i, j) such that r = gcd(a, b) = ia + jb
    """
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a  # Remember original a/b to remove
    ob = b  # negative values from return results
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob  # If neg wrap modulo orignal b
    if ly < 0:
        ly += oa  # If neg wrap modulo orignal a
    return a, lx, ly  # Return only positive values


class NotRelativePrimeError(ValueError):
    def __init__(self, a: int, b: int, d: int, msg: str = '') -> None:
        super().__init__(msg or "%d and %d are not relatively prime, divider=%i" % (a, b, d))
        self.a = a
        self.b = b
        self.d = d


def inverse(x: int, n: int) -> int:
    (divider, inv, _) = extended_gcd(x, n)
    if divider != 1:
        raise NotRelativePrimeError(x, n, divider)
    return inv


def randint(maxvalue: int):
    if maxvalue < 1:
        raise ValueError("maxvalue must be >= 1")

    bit_size = int(log2(maxvalue)) + 1

    tries = 0
    while True:
        value = getrandbits(bit_size)
        if value <= maxvalue:
            break

        if tries % 10 == 0 and tries:
            bit_size -= 1

        tries += 1

    if value > (2 ** bit_size) - 10:
        while gcd(value, maxvalue) != 1:
            value = randint(0, maxvalue)

    return value


def init_blind(n):
    for _ in range(1000):
        blind_r = randint(n - 1)
        if is_prime(n, blind_r):
            return blind_r


def blind_hide(n, e, message):
    with threading.Lock():
        blind_fac = init_blind(n)
        blind_fac_inverse = inverse(blind_fac, n)
        if blind_fac < 0:
            blind_fac = init_blind(n)
            blind_fac_inverse = inverse(blind_fac, n)
        else:
            # Reuse previous blinding factor.
            blind_fac = pow(blind_fac, 2, n)
            blind_fac_inverse = pow(blind_fac_inverse, 2, n)
    blinded = (message * pow(blind_fac, e, n)) % n
    return blinded, blind_fac_inverse


def unblind_hide(n, blinded, blind_fac_inverse):
    return (blind_fac_inverse * blinded) % n


def main():
    bit = 2048  # Choose a secure key size (e.g., 2048 bits)
    pub_priv_keys = gen_keys(bit)
    public_key, private_key = pub_priv_keys

    # You can now use the public and private keys for encryption and decryption
    plaintext = int(input("Enter plaintext to encrypt: "))
    ciphertext = pow_mod(plaintext, public_key[0], public_key[1])  # Encrypt with public key
    print(f'\nEncryption complete, ciphertext:\n{ciphertext}\n')

    decrypted = pow_mod(ciphertext, private_key, public_key[1])  # Decrypt with private key
    print(f'Decryption complete, plaintext:\n{decrypted}\n')


if __name__ == "__main__":
    main()
