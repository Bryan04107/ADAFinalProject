import secrets
from datetime import datetime

def string_to_hex(input_string):
    # Convert each character to its hexadecimal representation
    hex_string = ''.join(format(ord(char), '02x') for char in input_string)
    return hex_string


def hex_to_string(hex_string):
    # Convert pairs of hexadecimal characters to ASCII characters
    text = ''.join([chr(int(hex_string[i:i+2], 16)) for i in range(0, len(hex_string), 2)])
    return text


def pad(text, block_size):
    pad_value = block_size - len(text) % block_size
    return text + chr(pad_value) * pad_value


def unpad(padded_text):
    pad_value = ord(padded_text[-1])
    return padded_text[:-pad_value]


def generate_random_key():
    random_bytes = secrets.token_bytes(24)

    random_key_hex = random_bytes.hex()

    keys = []

    for i in range(0, 48, 16):
        keys.append(random_key_hex[i: i + 16])

    return keys


# PC-1 table (Permuted choice 1)
pc_1 = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

# PC-2 table (Permuted choice 2)
pc_2 = [14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32]

# IP table
ip = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# E table (Expansion function)
e = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# S boxes
s = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
      [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
      [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
      [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

     [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
      [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
      [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
      [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

     [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
      [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
      [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
      [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

     [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
      [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
      [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
      [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

     [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
      [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
      [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
      [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

     [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
      [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
      [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
      [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

     [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
      [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
      [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
      [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

     [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
      [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
      [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
      [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# P table (Permutation)
p = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# IP-1 table (Final permutation)
fp = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]


def hex_to_binary(hex_string):
    return format(int(hex_string, 16), '064b')


def left_circular_shift(eff_key, n):
    result = ""
    for i in range(n % len(eff_key), len(eff_key)):
        result += eff_key[i]
    for i in range(n % len(eff_key)):
        result += eff_key[i]

    return result


def get_56_bit_key(full_key, permuted_choice1):
    binary_key = hex_to_binary(full_key)

    effective_key = ""
    for i in permuted_choice1:
        effective_key += binary_key[i - 1]

    return effective_key


def generate_round_keys(effective_key, permuted_choice2):
    round_keys = []

    left = effective_key[0: 28]
    right = effective_key[28: 56]

    shifts_per_round = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    for i in range(16):
        left = left_circular_shift(left, shifts_per_round[i])
        right = left_circular_shift(right, shifts_per_round[i])
        current_shift_result = left + right

        current_round_key = ""
        for j in permuted_choice2:
            current_round_key += current_shift_result[j - 1]

        round_keys.append(current_round_key)

    return round_keys


def one_round(left, right, round_key, expansion_permutation, s_boxes, permutation):
    step_1_result = ""
    for i in expansion_permutation:
        step_1_result += right[i - 1]

    step_1_result_int = int(step_1_result, 2)
    round_key_int = int(round_key, 2)

    step_2_result = step_1_result_int ^ round_key_int
    step_2_result = format(step_2_result, "048b")

    blocks_for_s_box = []

    for i in range(0, len(step_2_result), 6):
        blocks_for_s_box.append(step_2_result[i: i + 6])

    step_3_result = ""

    for i in range(len(blocks_for_s_box)):
        row = blocks_for_s_box[i][0] + blocks_for_s_box[i][5]
        column = blocks_for_s_box[i][1: 5]

        s_box_result = s_boxes[i][int(row, 2)][int(column, 2)]

        step_3_result += format(s_box_result, "04b")

    step_4_result = ""
    for i in permutation:
        step_4_result += step_3_result[i - 1]

    left_int = int(left, 2)
    step_4_result_int = int(step_4_result, 2)

    step_5_result = format(left_int ^ step_4_result_int, "032b")

    left, right = right, step_5_result

    return left, right


def main_process(plaintext, round_keys, initial_permutation, expansion_permutation, s_boxes, permutation,
                 final_permutation, encryption):
    plaintext = hex_to_binary(plaintext)

    plaintext_after_ip = ""
    for i in initial_permutation:
        plaintext_after_ip += plaintext[i - 1]

    left = plaintext_after_ip[0: 32]
    right = plaintext_after_ip[32: 64]

    if not encryption:
        round_keys.reverse()

    for round_key in round_keys:
        left, right = one_round(left, right, round_key, expansion_permutation, s_boxes, permutation)

    result_after_rounds = right + left

    final_result = ""
    for i in final_permutation:
        final_result += result_after_rounds[i - 1]

    hex_final_result = format(int(final_result, 2), f'0{16}X')

    return hex_final_result


def DES(plaintext, full_key, permuted_choice1, permuted_choice2, initial_permutation, expansion_permutation,
        s_boxes, permutation, final_permutation, encryption):
    effective_key = get_56_bit_key(full_key, permuted_choice1)
    round_keys = generate_round_keys(effective_key, permuted_choice2)
    result = main_process(plaintext, round_keys, initial_permutation, expansion_permutation, s_boxes,
                          permutation, final_permutation, encryption)

    return result


def Triple_DES(plaintext, keys, permuted_choice1, permuted_choice2, initial_permutation, expansion_permutation, s_boxes,
               permutation, final_permutation, encryption):

    tmp_keys = keys.copy()
    if not encryption:
        tmp_keys.reverse()

    first_result = DES(plaintext, tmp_keys[0], permuted_choice1, permuted_choice2, initial_permutation,
                       expansion_permutation, s_boxes, permutation, final_permutation, encryption)

    # print("First result:", first_result)
    # print("")

    second_result = DES(first_result, tmp_keys[1], permuted_choice1, permuted_choice2, initial_permutation,
                        expansion_permutation, s_boxes, permutation, final_permutation, not encryption)

    # print("Second result:", second_result)
    # print("")

    final_result = DES(second_result, tmp_keys[2], permuted_choice1, permuted_choice2, initial_permutation,
                       expansion_permutation, s_boxes, permutation, final_permutation, encryption)

    return final_result


def testing_speed(message_to_encrypt):
    padded = pad(message_to_encrypt, 8)
    padded_hex = string_to_hex(padded)

    encrypted_times = []
    decryption_times = []

    blocks = []
    for index in range(0, len(padded_hex), 16):
        blocks.append(padded_hex[index: index + 16])

    all_keys = generate_random_key()

    for i in range(10):
        ciphertext_blocks = []
        ciphertext = ""
        start1 = datetime.now()
        for block in blocks:
            block_result = Triple_DES(block, all_keys, pc_1, pc_2, ip, e, s, p, fp, True)
            ciphertext_blocks.append(block_result)
            ciphertext += block_result
        end1 = datetime.now()

        encryption_time = (end1 - start1).total_seconds() * 10 ** 3

        encrypted_times.append(encryption_time)

        decrypted_blocks = []
        decrypted_text = ""
        start2 = datetime.now()
        for block in ciphertext_blocks:
            block_result = Triple_DES(block, all_keys, pc_1, pc_2, ip, e, s, p, fp, False)
            decrypted_blocks.append(block_result)
            decrypted_text += block_result

        decrypted_text = unpad(hex_to_string(decrypted_text))

        end2 = datetime.now()

        decryption_time = (end2 - start2).total_seconds() * 10 ** 3

        decryption_times.append(decryption_time)

        if decrypted_text != message_to_encrypt:
            print("WEEWOOWEEWOO")
            break

        print(i)
    print("Encryption average:", (sum(encrypted_times) / (len(encrypted_times))))
    print("Decryption average:", (sum(decryption_times) / (len(decryption_times))))


input_text = '''Never gonna give you up, never gonna let you down'''
testing_speed(input_text)
#
# plain_text = "Never gonna give you up, never gonna let you down"
# padded = pad(plain_text, 8)
# padded_hex = string_to_hex(padded)
#
# blocks = []
# for index in range(0, len(padded_hex), 16):
#     blocks.append(padded_hex[index: index + 16])
#
# all_keys = generate_random_key()
#
# print("Triple DES")
# print("")
#
# print("Plain text:", plain_text)
# print("")
#
# print("Encryption")
# print("----------")
#
# ciphertext_blocks = []
# ciphertext = ""
# for block in blocks:
#     block_result = Triple_DES(block, all_keys, pc_1, pc_2, ip, e, s, p, fp, True)
#     ciphertext_blocks.append(block_result)
#     ciphertext += block_result
#
# print("Ciphertext:", ciphertext)
# print("")
#
# print("Decryption")
# print("----------")
#
# decrypted_blocks = []
# decrypted_text = ""
# for block in ciphertext_blocks:
#     block_result = Triple_DES(block, all_keys, pc_1, pc_2, ip, e, s, p, fp, False)
#     decrypted_blocks.append(block_result)
#     decrypted_text += block_result
#
# decrypted_text = unpad(hex_to_string(decrypted_text))
#
# print("Decrypted text:", decrypted_text)
# print("")
