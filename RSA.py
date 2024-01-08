import random
from datetime import datetime


def is_prime(num):
    if num <= 1:
        return False
    if num % 2 == 0:
        return False
    for i in range(3, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True


def generate_prime(bits):
    while True:
        key = random.getrandbits(bits)
        if is_prime(key):
            return key


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def modinv(e, phi):
    first, second, t1, t2 = phi, e, 0, 1
    while second != 0:
        quotient, remainder = first // second, first % second
        t = t1 - t2 * quotient
        first, second, t1, t2 = second, remainder, t2, t
    return t1 % phi


def generate_keypair(bits):
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(1, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = modinv(e, phi)

    return (n, e), (n, d)


def generate_keypair_for_testing():
    p = 340282366920938463463374607431768211297
    q = 270640123725608296758355214238259674023
    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(1, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = modinv(e, phi)

    return (n, e), (n, d)


def encrypt(public_key, plaintext):
    n, e = public_key
    encrypted = []
    for char in plaintext:
        unicode = ord(char)
        cipher = pow(unicode, e, n)
        encrypted.append(cipher)
    return encrypted


def decrypt(private_key, ciphertext):
    n, d = private_key
    decrypted = ''
    for char in ciphertext:
        unicode = pow(char, d, n)
        character = chr(unicode)
        decrypted += character
    return decrypted


def speed_test(message_test):
    public_key, private_key = generate_keypair_for_testing()
    encrypted_times = []
    decryption_times = []
    for i in range(10):
        message_to_encrypt = message_test
        start1 = datetime.now()
        encrypted = encrypt(public_key, message_to_encrypt)
        end1 = datetime.now()

        encryption_time = (end1 - start1).total_seconds() * 10 ** 3

        encrypted_times.append(encryption_time)

        start2 = datetime.now()
        decrypted = decrypt(private_key, encrypted)
        end2 = datetime.now()

        decryption_time = (end2 - start2).total_seconds() * 10 ** 3

        decryption_times.append(decryption_time)

        if decrypted != message_to_encrypt:
            print("WEEWOOWEEWOO")
            break

        print(i)

    print("Encryption average:", (sum(encrypted_times) / (len(encrypted_times))))
    print("Decryption average:", (sum(decryption_times) / (len(decryption_times))))


speed_test('''Never gonna give you up, never gonna let you down''')

# Example usage
# public_key, private_key = generate_keypair_for_testing()
# message = "Never gonna give you up, never gonna let you down"
# encrypted_message = encrypt(public_key, message)
# decrypted_message = decrypt(private_key, encrypted_message)

# print("Original Message:", message)
# print("Encrypted Message:", encrypted_message)
# print("Decrypted Message:", decrypted_message)
