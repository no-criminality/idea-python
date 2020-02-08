#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Алгоритм шифрования IDEA
Версия Python - 3.6+
'''

import sys
import secrets
import getpass
from bitstring import BitArray

KEY_LEN = 16
BLOCK_LEN = 8


def split_text(string_bytes, block_size, sub_size):
    '''
    Преобразование и разбиение строки на блоки для дальнейшего
    шифрования/дешифрования
    '''
    # Разбиение на подблоки
    subblocks = [
        string_bytes[
            i:i + sub_size] for i in range(0, len(string_bytes), sub_size)]
    if block_size == 0:
        return subblocks
    else:
        # Сборка подблоков в блоки
        block = [subblocks[i:i + block_size] for i in range(
            0, len(subblocks), block_size)]

        return block


def alignment(align_message, block_lenght, kind):
    '''Выравнивание длины сообщения или ключа'''
    if kind == 'text':
        # Установка единичного байта
        align_message = align_message + b'\x01'
        # Дополнение случайными байтами
        while len(align_message) % (block_lenght) != 0:
            align_message += secrets.token_bytes(1)
    elif kind == 'key':
        # Дополнение единичными байтами ключа
        while len(align_message) % (block_lenght) != 0:
            align_message = align_message + b'\x01'
    else:
        print('Введите допустимый аргумент функции text_to_byte()!')
        sys.exit()

    return align_message


def rm_right(byte_string):
    '''Удаление конечных случайных байтов'''
    if b'\x01' in byte_string:
        byte_string = byte_string[:byte_string.index(b'\x01')]

    return byte_string


def text_to_byte(message, block_lenght, kind):
    '''Преобразование входной строки в байтовую и выравнивание'''
    message = message.encode('unicode-escape')
    # Выравнивание сообщения
    if len(message) % (block_lenght) != 0:
        message = alignment(message, block_lenght, kind)

    return message


def int_to_bytes(int_value):
    '''Перевод из типа int в строку байтов'''
    return int_value.to_bytes((int_value.bit_length() // 8) + 1, 'big')


def add(value_1, value_2):
    '''Сложение по модулю 2 ** 16'''
    return (value_1 + value_2) & 0xFFFF


def multiply(value_1, value_2):
    '''Умножение по модулю (2 ** 16) + 1'''
    if value_1 == 0x0000:
        value_1 = 0x10000
    if value_2 == 0x0000:
        value_2 = 0x10000
    result = (value_1 * value_2) % 0x10001
    if result == 0x10000:
        result = 0x0000
    return result


def add_inverse(value):
    '''Аддитивная инверсия'''
    return (-value) & 0xFFFF


def multi_inverse(value):
    '''Мультипликативная инверсия'''
    if value == 0:
        return 0
    else:
        return pow(value, 0xFFFF, 0x10001)


def key_gen(key_bits):
    '''Генерация раундовых ключей'''
    # Подключ для первого раунда
    key_long = split_text(key_bits.bin, 0, KEY_LEN)

    # Циклический сдвиг влево на 25 позиций
    for i in range(0, 6):
        key_bits.rol(25)
        round_key = split_text(key_bits.bin, 0, KEY_LEN)
        key_long.extend(round_key)
    del key_long[52:]

    return key_long


def encryption(block, key_bits):
    '''Шифрование блоков открытого текста'''
    key_int = []
    encrypted_list = []

    # Генерация подключей
    key_long_encrypt = key_gen(key_bits)
    # Подключи в числовом представлении
    for onesubkey in key_long_encrypt:
        key_int.append(int(onesubkey, 2))

    # Перебор блоков
    for sub in block:
        # Четыре подблока открытого текста в числовом представлении
        sub_first = int(sub[0], 2)
        sub_second = int(sub[1], 2)
        sub_third = int(sub[2], 2)
        sub_fourth = int(sub[3], 2)

        # 8 раундов
        for rnd in range(0, 48, 6):
            a_var = multiply(sub_first, key_int[rnd])
            b_var = add(sub_second, key_int[rnd + 1])
            c_var = add(sub_third, key_int[rnd + 2])
            d_var = multiply(sub_fourth, key_int[rnd + 3])
            e_var = a_var ^ c_var
            f_var = b_var ^ d_var
            g_var = multiply(e_var, key_int[rnd + 4])
            h_var = add(f_var, g_var)
            i_var = multiply(h_var, key_int[rnd + 5])
            j_var = add(g_var, i_var)

            sub_first = a_var ^ i_var
            sub_second = b_var ^ j_var
            sub_third = c_var ^ i_var
            sub_fourth = d_var ^ j_var
            sub_second, sub_third = sub_third, sub_second

        # Заключительное преобразование
        w_var = multiply(sub_first, key_int[48])
        x_var = add(sub_third, key_int[49])
        y_var = add(sub_second, key_int[50])
        z_var = multiply(sub_fourth, key_int[51])

        # 64 битный блок в десятичном представлении
        encrypted_int = [w_var, x_var, y_var, z_var]

        # Блоки в шестнадцатеричном представлении
        for value in encrypted_int:
            encrypted_list.append(hex(value)[2:].zfill(4).upper())

    return ''.join(encrypted_list)


def decryption(block, key_bits):
    '''Расшифрование блоков'''
    decrypted_bytes = []
    key_int = []

    # Генерация подключей
    key_long_decrypt = key_gen(key_bits)
    # Подключи в числовом представлении
    for onesubkey in key_long_decrypt:
        key_int.append(int(onesubkey, 2))

    # Перебор блоков
    for sub in block:
        # Четыре подблока открытого текста в числовом представлении
        sub_first = int(sub[0], 2)
        sub_second = int(sub[1], 2)
        sub_third = int(sub[2], 2)
        sub_fourth = int(sub[3], 2)

        # 8 раундов
        for rnd in range(51, 3, -6):
            if rnd == 51:
                a_var = multiply(sub_first, multi_inverse(key_int[rnd - 3]))
                b_var = add(sub_second, add_inverse(key_int[rnd - 2]))
                c_var = add(sub_third, add_inverse(key_int[rnd - 1]))
                d_var = multiply(sub_fourth, multi_inverse(key_int[rnd]))
            else:
                a_var = multiply(sub_first, multi_inverse(key_int[rnd - 3]))
                b_var = add(sub_second, add_inverse(key_int[rnd - 1]))
                c_var = add(sub_third, add_inverse(key_int[rnd - 2]))
                d_var = multiply(sub_fourth, multi_inverse(key_int[rnd]))

            e_var = a_var ^ c_var
            f_var = b_var ^ d_var
            g_var = multiply(e_var, key_int[rnd - 5])
            h_var = add(f_var, g_var)
            i_var = multiply(h_var, key_int[rnd - 4])
            j_var = add(g_var, i_var)

            sub_first = a_var ^ i_var
            sub_second = b_var ^ j_var
            sub_third = c_var ^ i_var
            sub_fourth = d_var ^ j_var
            sub_second, sub_third = sub_third, sub_second

        # Заключительное преобразование
        w_var = multiply(sub_first, multi_inverse(key_int[0]))
        x_var = add(sub_third, add_inverse(key_int[1]))
        y_var = add(sub_second, add_inverse(key_int[2]))
        z_var = multiply(sub_fourth, multi_inverse(key_int[3]))

        # 64 битный блок в десятичном представлении
        decrypted_int = [w_var, x_var, y_var, z_var]

        # Блок в байтовом представлении
        for value in decrypted_int:
            decrypted_bytes.append(int_to_bytes(value))

        # Объединение байтов в одну строку
        decrypted_bytes_str = b''.join(decrypted_bytes)
        # Удаление конечной случайной последовательности
        decrypted_bytes_str = rm_right(decrypted_bytes_str)

    return decrypted_bytes_str.decode('unicode-escape')


def key_input():
    '''Ввод ключа'''
    key = getpass.getpass('\nВведите ключ: ')
    if key == '':
        sys.exit('\nОшибка. Введите ключ!')

    return key


def menu_item_1():
    '''Зашифровать строку, записать в файл'''
    plaintext = input('\nВведите строку для шифрования: ')
    if plaintext == '':
        print('\nОшибка. Введите строку!')
        return
    key_string = key_input()

    print('\n...Шифрование...')

    # Преобразование сообщения и ключа в строки байтов
    plaintext_bytes = text_to_byte(plaintext, BLOCK_LEN, 'text')
    key_bytes_encrypt = text_to_byte(key_string, KEY_LEN, 'key')

    # Битовые массивы с открытым сообщением и секретным ключем
    plaintext_bit_array = BitArray(plaintext_bytes)
    encrypt_key_bit_array = BitArray(key_bytes_encrypt)

    print('\nОткрытое сообщение \
в битовом представлении:', plaintext_bit_array.bin)

    # Разбиение сообщения на блоки и подблоки
    plaintext_block = split_text(plaintext_bit_array.bin, 4, KEY_LEN)
    print('\nВходные блоки и подблоки сообщения:', plaintext_block)

    # Шифрование
    ciphertext = encryption(plaintext_block, encrypt_key_bit_array)
    print('\nЗашифрованное сообщение:', ciphertext)

    # Запись в файл
    choice = input('Записать результат в файл?[Y/д]: ').lower()
    if choice in ('y', 'д', 'yes', 'да'):
        filename = input('\nВведите название файла: ')
        if filename == '':
            print('\nОшибка. Введите название файла!')
            return
        filename += '.idea'
        file_crypt = open(filename, 'w', encoding='utf-8')
        file_crypt.write(ciphertext)
        file_crypt.close()
        print('\nФайл', filename, 'записан успешно.')
    else:
        print('\nОтмена.')
        return


def menu_item_2():
    '''Расшифровать строку'''
    ciphertext = input('\nВведите строку для расшифровки: ')
    if ciphertext == '':
        print('\nОшибка. Введите строку!')
        return
    key_string = key_input()

    print('\n...Расшифровка...')

    # Преобразование ключа в строку байтов
    key_bytes_decrypt = text_to_byte(key_string, KEY_LEN, 'key')

    # Битовые массивы с закрытым сообщением и секретным ключем
    try:
        ciphertext_bit_array = BitArray('0x' + ciphertext)
    except ValueError:
        print('\nОшибка. Введена неверная строка!')
        return

    decrypt_key_bit_array = BitArray(key_bytes_decrypt)
    print('\nЗашифрованное сообщение \
в битовом представлении:', ciphertext_bit_array.bin)

    # Разбиение сообщения на блоки и подблоки
    ciphertext_block = split_text(ciphertext_bit_array.bin, 4, KEY_LEN)
    print('\nВходные блоки и подблоки сообщения:', ciphertext_block)

    deciphertext = decryption(ciphertext_block, decrypt_key_bit_array)
    print('\nРасшифрованное сообщение:', deciphertext)


def menu_item_3():
    '''Расшифровать строку из файла'''
    filename = input('\nВведите название или путь к файлу: ')
    if '.idea' not in filename:
        filename += '.idea'

    if filename in ('.idea', ''):
        print('\nОшибка. Введите название или путь к файлу!')
        return

    try:
        file_decrypt = open(filename, 'r', encoding='utf-8')
        ciphertext = file_decrypt.read(10000)
        file_decrypt.close()
    except FileNotFoundError:
        print('\nОшибка. Файл не найден!')
        return

    key_string = key_input()

    if ciphertext == '':
        print('\nОшибка. Файл пуст!')
        return

    print('\n...Расшифровка...')

    # Преобразование ключа в строку байтов
    key_bytes_decrypt = text_to_byte(key_string, KEY_LEN, 'key')

    # Битовые массивы с закрытым сообщением и секретным ключем
    try:
        ciphertext_bit_array = BitArray('0x' + ciphertext)
    except ValueError:
        print('\nОшибка. Данные в файле невозможно расшифровать!')
        return

    decrypt_key_bit_array = BitArray(key_bytes_decrypt)
    print('\nЗашифрованное сообщение \
в битовом представлении:', ciphertext_bit_array.bin)

    # Разбиение сообщения на блоки и подблоки
    ciphertext_block = split_text(ciphertext_bit_array.bin, 4, KEY_LEN)
    print('\nВходные блоки и подблоки сообщения:', ciphertext_block)

    deciphertext = decryption(ciphertext_block, decrypt_key_bit_array)
    print('\nРасшифрованное сообщение:', deciphertext)


def main():
    '''Главное меню программы'''
    print('''
### ######  #######    #
 #  #     # #         # #
 #  #     # #        #   #
 #  #     # #####   #     #
 #  #     # #       #######
 #  #     # #       #     #
### ######  ####### #     #
''')

    while True:
        print('''
**********************

1. Зашифровать строку
2. Расшифровать строку
3. Расшифровать строку из файла
0. Выход
''')

        select = input('Выберите действие: ')

        if select == '0':
            print('\nВыход')
            sys.exit()
        elif select == '1':
            menu_item_1()
        elif select == '2':
            menu_item_2()
        elif select == '3':
            menu_item_3()

        else:
            print('\nОшибка. Неизвестный ввод!')


main()
