#!/usr/bin/python
# TODO: fix writing password to file after multiple iterations of random generation
#       fix salting
# 	use os.path for file handling
import scrypt
import sys, argparse 
import random
import os
from base64 import b64encode
from base64 import b64decode
import bcrypt
#import sqlite3


def generate_pw(chars, length):
    password = ''.join(random.choice(chars) for n in range(length))
    print(password)
    re = input("Enter 'n' to generate new password or 's' to store password: ")
    if re == 'n':
        generate_pw(chars,length)
    elif re == 's':
        return password
def new():
    all_symbols = '''abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@$%^&*()_+-=[]\{}|:";'<>?,./'''
    letters_numbers = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
    address = input('Enter the account address: ')
    if len(address) < 1:
         print('Invalid entry')
         new()
    user = input('Enter the account username: ')
    if len(user) < 1:
         print('Invalid entry')
         new()
    password_types = [all_symbols, letters_numbers]
    for i in password_types:
        print(password_types.index(i), ': ', i, '\n')
    pt = input('Select password type: ')
    if pt == '0':
        pt = all_symbols
    elif pt == '1':
        pt = letters_numbers
    else:
        print('Invalid selection')
        new()
    r = input('Enter number of symbols (int): ')
    try:
        r = int(r)
    except TypeError:
        print('Input not type int')
    password = generate_pw(pt,r)
    algs = ['bcrypt', 'scrypt']	# User should be able to update libraries for crypto
    for i in algs:
        print(algs.index(i), i)
    crypt_alg = input('Select cryptographic algorithm: ')
    if crypt_alg == '0':	# This needs abstracting
       bcrypt_hash(password)
    elif crypt_alg == '1':
       scrypt_hash(password)    

def save(data):
    algs = ['bcrypt', 'scrypt'] # User should be able to update libraries for crypto
    alg_choice = {}
    for i in algs:
        alg_choice[i] = algs.index(i) + 1
        print(algs.index(i) + 1, i)
    crypt_alg = input('Select cryptographic algorithm: ')
    for i in alg_choice:
        if int(crypt_alg) == alg_choice[i]:        # This needs abstracting
           bcrypt_encrypt(data)
        elif int(crypt_alg) == alg_choice[i]:
            scrypt_hash(data)

def scan(scan_file):
    '''This should read from a file the address, username, and password 
       as arbitrarily separated, e.g. comma, newline, tab '''
    #scan_file = input('Enter file: ')
    data = []
    try:
        with open(scan_file, 'r') as f:
            for line in f:
                if line == '\n':
                    pass
                else:
                    data.append(line)
    except IOError:
        print('File not found')
    save(data)

def scrypt_hash(password):
    salt = b64encode(os.urandom(64))
    hashed_password = scrypt.hash(password, salt)
    print('Writing ' + password + ' to secret/test')
    with open('secret/test','ab') as f:
        f.write(hashed_password)

def scrypt_verify():
    attempt = input("Enter password: ")
    print("Verifying...")
    with open('secret/test','rb') as f:
        for i in f:
            print(i)
            if scrypt.hash(i, salt) == hashed_password:
                print("Password accepted ")

def bcrypt_encrypt(data):
    log = input('Enter logs rounds: ')
    try:
        log = int(log)
    except TypeError:
        print('Input not integer, try again.')
        bcrypt_encrypt(data)
    secret_lines = []
    for i in data:
        secret_lines.append(bcrypt.hashpw(i.encode(), bcrypt.gensalt(log)))
    try:
        with open('secret/bcrypt_test','ab') as f:
            for i in secret_lines:
                print(i)
                f.write(i)
    except IOError:
        print('File not found')
    
def bcrypt_hash(password):
    log = input('Enter log rounds: ')
    try:
        log = int(log)
    except TypeError:
        print('Input not integer, try again.')
        bcrypt_hash(password) 
    #int(log)
    #encoded_password = b64encode(password)
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt(log))
    print('Storing password...')
    with open('secret/bcrypt_test', 'ab') as f:
        f.write(hashed_password, '\n')

def bcrypt_verify():
    attempt = input('Enter password: ')
    matches = []
    try:
        with open('secret/bcrypt_test', 'rb') as f:
            for i in f: 
                if bcrypt.hashpw(attempt.encode(), i) == i:
                    matches.append(i)
        if len(matches) > 0:
            print('Password accepted')
        else: 
            print('Password denied')
    
    except IOError:
        print('File not found')                            
        
def main():
    #print("""
    #            PassMan
    #    
    #    Usage: python passman.py <options> <arguments>
    #    Options: 'new': generate and hash new password\n""")
    
    #parser = argparse.ArgumentParser(description = 'Passman \n Text encryption tool')
    #subparsers = p.add_subparsers()
    # = subparsers.add_parser('
    #parser.add_argument('-n', '--new')
    #parser.add_argument('-v', '--verify')
    #parser.add_argument('')
    #parser.add_argument('')
    for arg in sys.argv:
        if arg == '-n':
            new()
        elif arg == '-v':
            bcrypt_verify()
        elif arg == '-c':
            pass
        elif arg == '-s':
            scan(sys.argv[sys.argv.index(arg) + 1])

if __name__ == '__main__':
    main()
