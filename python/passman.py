#!/usr/bin/python
''' TODO:
        authenticate() prompts for password, create user, change user
            crypt function?
                
        fix writing password to file after multiple iterations of random generation
        make default settings without cli args
        make option for hashing single strings
        get scrypt working
        get option to input new encrypting or hashing functions
        use os.path for file handling
'''
import scrypt
import sys, argparse 
import random
import os
from base64 import b64encode
from base64 import b64decode
import bcrypt
#import sqlite3
class User():
    def __init__(self, username, pass_phrase):
        self.username = username
        self.pass_phrase = pass_phrase 
    def new_user():
        username_entry = input('Enter username: ')
        if len(username) < 1:
            print('Invalid entry')
            new_user()
        pass_phrase_entry = input('Enter passphrase: ')
        if len(pass_phrase) < 1:
            print('Invalid entry')
            new_user()
    def authenticate():
        username = input('Enter username: ')
        if len(username) < 1:
            print('Invalid entry')
            authenticate()
        pass_phrase = input('Enter passphrase: ')
        if len(pass_phrase) < 1:
            print('Invalid entry')
            authenticate()
                
    
def generate_pw(chars, length):
    password = ''.join(random.choice(chars) for n in range(length))
    print(password)
    re = input("Enter 'n' to generate new password or 's' to store password: ")
    if re == 'n':
        generate_pw(chars,length)
    elif re == 's':
        return password
def new(location):
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
        #pt_choices[i] = password_types.index(i) + 1
        print(password_types.index(i) + 1, ': \n', i)
    pt = input('Select password type: ')
    pass_type = None
    for i in password_types:
        if int(pt) == password_types.index(i) + 1:
            pass_type = i
    r = input('Enter number of symbols (int): ')
    try:
        r = int(r)
    except TypeError:
        print('Input not type int')
    password = generate_pw(pass_type,r)
    data = [address, user, password]
    save(data, location)

def save(data, location):
    '''I would like this eventually to be modular so that users can include new hash libraries
    but without risk of over the shoulder attack. For now only bcrypt and scrypt are available
    and are hard coded user options.'''
    funcs = ['bcrypt_encrypt', 'scrypt']
    for i in funcs:
        print(funcs.index(i) + 1, i)
    func_select = input('Select cryptographic function: ')
    if func_select == '1':
        bcrypt_encrypt(data, location)
    elif func_select  == '2':
        scrypt_encrypt(data)
        #elif int(alg) == alg_choice[i]:
            #scrypt_hash(data)

def scan(location):
    '''This should read from a file the address, username, and password 
       as arbitrarily separated, e.g. comma, newline, tab '''
    data = []
    try:
        with open(location, 'r') as f:
            for line in f:
                if line == '\n':
                    pass
                else:
                    data.append(line)
    except IOError:
        print('File not found')
    location = input('Enter save file location: ')
    save(data, location)

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

def bcrypt_encrypt(data, location):
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
        with open(location,'ab') as f:
            for i in secret_lines:
                print(i)
                f.write(i)
                f.write(b'\n')
    except IOError:
        print('File not found')
    
def bcrypt_hash(password):
    log = input('Enter log rounds: ')
    try:
        log = int(log)
    except TypeError:
        print('Input not integer, try again.')
        bcrypt_hash(password) 
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt(log))
    print('Storing password...')
    with open('secret/bcrypt_test', 'ab') as f:
        f.write(hashed_password, '\n')

def bcrypt_verify(data):
    attempt = input('Enter password: ')
    matches = []
    try:
        with open(data, 'rb') as f:
            for i in f:
                i = i.strip(b'\n') 
                if bcrypt.hashpw(attempt.encode(), i) == i:
                    matches.append(i)
                    print('Match found: ', attempt)
                else:
                    print('Failed...')
        print(matches)
    except IOError:
        print('File not found')                            
    
def main():
'''

1 start command line
2 parse args, opts
3 prompt for auth or to create user

'''
    print("""
                PassMan
        
        Usage: python passman.py <options> <arguments>
        Options: 'new': generate and hash new password\n""")
    user_status = User.authenticate()
    for arg in sys.argv:
        if arg == '-n':
            new(sys.argv[sys.argv.index(arg) + 1])
        elif arg == '-v':
            bcrypt_verify(sys.argv[sys.argv.index(arg) + 1])
        elif arg == '-c':
            pass
        elif arg == '-s':
            scan(sys.argv[sys.argv.index(arg) + 1])

if __name__ == '__main__':
    main()
