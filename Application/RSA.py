
import random
import time
# Greatest Common Divisor
def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b


def mod_inverse(x, n):     # (x * x_inv) % n == 1
    original_n = n
    x1, x2 = 0, 1
    while x > 1:
        q = x // n
        x, n = n, x % n
        x1, x2 = x2 - q * x1, x1
    if x2 < 0:
        x2 += original_n
    return x2


def probin(bit): #bit: how many bits wants to be generate
    #randomly generate bid odd number
    list = []
    list.append('1')
    for i in range(bit - 2):
        c = random.choice(['0', '1'])
        list.append(c)
    list.append('1')
    res = int(''.join(list), 2)
    return res

def pow_mod(p, q, n): # p^q mod n, p:Base, q:Exponent, n:Modulus
    #Montgomery Reduction
    res = 1
    while q:
        if q & 1:
            res = (res * p) % n
        q >>= 1
        p = (p * p) % n
    return res

def prime_miller_rabin(a, n): # n: number needed to be test  a: random.randint(2, n - 1)
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

    #Use miller rabin method to test whether the genertated number is prime number
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
        for _ in range(50):  # If no prime is found within 50 odd numbers around the pseudo prime, generate a new pseudo prime
            if prime_test(prime_candidate, 5):
                return prime_candidate
            prime_candidate += 2  # Move to the next odd number


if __name__ == '__main__':
    start_time = time.time()  # Start timing

    p = get_prime(500)  # Key p
    q = get_prime(550)  # Key q
    n = p * q  # Public n
    phi_n = (p - 1) * (q - 1)  # Euler's totient function

    e = 65537
    while gcd(e, phi_n) != 1:
        e -= 1

    d = mod_inverse(e, phi_n)

    key_generation_time = time.time()  # Mark key generation completion time
    print(f'Key generation time: {key_generation_time - start_time:.2f} seconds\n')

    print('Private keys (p, q, d):')
    print(f'p: {p}\nq: {q}\nd: {d}\n')

    print('Public keys (n, e):')
    print(f'n: {n}\ne: {e}\n')

    plaintext = int(input("Enter plaintext to encrypt: "))

    encryption_start = time.time()  # Start timing encryption
    ciphertext = pow_mod(plaintext, e, n)  # Encrypt
    encryption_time = time.time()  # Mark encryption completion time
    print(f'\nEncryption time: {encryption_time - encryption_start:.2f} seconds')
    print(f'Ciphertext:\n{ciphertext}\n')

    decryption_start = time.time()  # Start timing decryption
    decrypted = pow_mod(ciphertext, d, n)  # Decrypt
    decryption_time = time.time()  # Mark decryption completion time
    print(f'Decryption time: {decryption_time - decryption_start:.2f} seconds')
    print(f'Plaintext:\n{decrypted}\n')

    total_time = time.time() - start_time  # Total runtime
    print(f'Total runtime: {total_time:.2f} seconds')





