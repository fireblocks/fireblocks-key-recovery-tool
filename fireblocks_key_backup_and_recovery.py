#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from utils import recover
import argparse
import getpass
import sys
from termcolor import colored
import inquirer
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from utils.public_key_verification import create_short_checksum
from utils.public_key_verification import create_and_pop_qr
import animation

CREATE_RECOVERY_KEY_PAIR = 'CREATE_RECOVERY_KEY_PAIR'
VERIFY_PUBLIC_KEY = 'VERIFY_PUBLIC_KEY'
VERIFY_RECOVERY_PACKAGE = 'VERIFY_RECOVERY_PACKAGE'
REVEAL_PRV_BACKUP_KEY = 'REVEAL_PRV_BACKUP_KEY'
EXIT_MENU = 'EXIT_MENU'

DEFAULT_KEY_FILE_PREFIX = 'fb-recovery'

SHORT_PHRASE_VERIFICATION = 'SHORT_PHRASE_VERIFICATION'
QR_CODE_VERIFICATION = 'QR_CODE_VERIFICATION'

KEY_SIZE = 4096
PUBLIC_EXPONENT = 65537

menu_options = {
    CREATE_RECOVERY_KEY_PAIR: '1. Create a recovery key pair',
    VERIFY_PUBLIC_KEY: '2. Verify the public recovery key to create a backup via the console',
    VERIFY_RECOVERY_PACKAGE: '3. Verify the key backup package',
    REVEAL_PRV_BACKUP_KEY: '4. Reveal the private workspace keys',
    EXIT_MENU: '5. Exit'
}


public_key_verification_menu_options = {
    QR_CODE_VERIFICATION: '1. Display a scannable public key QR code',
    SHORT_PHRASE_VERIFICATION: '2. Display a public key short phrase',
    EXIT_MENU: '3. Exit'
}


def create_rsa_key_pair():
    print("""You are about to create a public and private recovery key
The private recovery key will be encrypted with a passphrase that you choose.""")

    change_file_name = inquirer.confirm('The key files are named "fb-recovery-public.pem" and "fb-recovery-private.pem" by default. Do you want to change these names?', default=False)

    if change_file_name:
        key_prefix = inquirer.text(
            message='Enter a name for your recovery key files. The file names will be suffixed with  "-public.pem" and "-private.pem", respectively')
    else:
        key_prefix = DEFAULT_KEY_FILE_PREFIX

    passphrase = inquirer.password(
        message='Choose a private recovery key passphrase that you will remember')
    verify_passphrase = inquirer.password(
        message='Confirm the passphrase')

    print('Verifying...')
    if not passphrase or not verify_passphrase or passphrase != verify_passphrase:
        print(colored('\nVerifying passphrase failed! Please try again', 'red'))
        return

    public_key_file_name = key_prefix + '-public.pem'
    private_key_file_name = key_prefix + '-private.pem'

    if(os.path.exists(public_key_file_name) or os.path.exists(private_key_file_name)):
        print(colored("\nPublic or private key files with this name already exists!. Can't override\n", 'red', attrs=['bold']))
        return

    wait = animation.Wait('spinner', colored('\nGenerating key pair...', 'yellow'))
    wait.start()

    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE
    )

    wait.stop()

    encrypted_pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(
            bytes(passphrase, encoding='utf-8')
        )
    )

    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


    private_key_file = open(private_key_file_name, 'w')
    private_key_file.write(encrypted_pem_private_key.decode())
    private_key_file.close()

    public_key_file = open(public_key_file_name, 'w')
    public_key_file.write(pem_public_key.decode())
    public_key_file.close()

    print('\nThe recovery key pair was created')

def pop_validate_pub_key_menu():
    print('\n')
    return inquirer.list_input(message=colored(
        'Choose the verification method: ', 'green'),
        choices=public_key_verification_menu_options.values())

def is_pem_public_key(key_str):
    try:
        serialization.load_pem_public_key(key_str.encode())
        return True
    except (ValueError, TypeError, AttributeError):
        return False
    
def verify_public_key():
    print('Workspace admins can approve the key backup using the Fireblocks mobile app.\n')

    file_path = inquirer.text(
        message='Enter the public recovery key file name or press "Enter" to use the default name', default=DEFAULT_KEY_FILE_PREFIX + '-public.pem')

    if not os.path.exists(file_path):
        print(colored('\nPublic key file: {} not found.\n'.format(file_path), 'red', attrs=['bold']))
        return

    with open(file_path, 'r') as _pub_key:
        pub_key = _pub_key.read()
    
    if not is_pem_public_key(pub_key):
        print(colored('\nPublic key file: {} is not a valid PEM public key.\n'.format(file_path), 'red', attrs=['bold']))
        return

    cont = True
    while cont:
        menu_options = pop_validate_pub_key_menu()
        if menu_options == public_key_verification_menu_options[QR_CODE_VERIFICATION]:
            create_and_pop_qr(pub_key)
            print(colored(
                "Opened the QR image file for you (local run only), and saved it on your machine as pub_key_qr.png", "cyan"))
        elif menu_options == public_key_verification_menu_options[SHORT_PHRASE_VERIFICATION]:
            print(colored("The public key short phrase is: " + colored(create_short_checksum(pub_key), attrs=['bold']), "cyan"))
        elif menu_options == public_key_verification_menu_options[EXIT_MENU]:
            cont=False
        else:
            print(colored('Not a valid choise', 'red', attrs=['bold']))
            exit(-1)


def get_recover_keys_args():
    questions = [
        inquirer.Text('backup', message='Enter the backup zip file name'),
        inquirer.Text('key', message='Enter the rsa private key file name or press enter for default', default=DEFAULT_KEY_FILE_PREFIX + '-private.pem'),
        inquirer.Text('mobile_key', message=colored('Optional', attrs=['bold']) + ' Enter the mobile RSA private key file or press enter'),
    ]

    return inquirer.prompt(questions)


def recover_keys(show_xprv=False):
    #args = get_recover_keys_args()
    key = inquirer.text(message='Enter the private recovery key file name or press "Enter" to use the default name', default=DEFAULT_KEY_FILE_PREFIX + '-private.pem')
    if not os.path.exists(key):
        print('RSA key: {} not found.'.format(key))
        exit(-1)

    with open(key, 'r') as _key:
        key_file = _key.readlines()
        if 'ENCRYPTED' in key_file[0] or 'ENCRYPTED' in key_file[1]:
            key_pass = inquirer.password(message='Enter your private recovery key passphrase')
        else:
            key_pass = None

    is_self_drs = inquirer.confirm(
        message="Are you using an auto-generated passphrase? (This is not a default feature)", default=False)
    mobile_key = None
    mobile_key_pass = None

    if not is_self_drs:
        passphrase = inquirer.password(message='Enter the mobile recovery passphrase')
    else:
        mobile_key = inquirer.text(
            message="Enter the private key file name that you used for your auto-generated passphrase")
        with open(mobile_key, 'r') as _key:
            key_file = _key.readlines()
            if 'ENCRYPTED' in key_file[0] or 'ENCRYPTED' in key_file[1]:
                mobile_key_pass = inquirer.password(message='Enter the passphrase for the private key file')

    backup = inquirer.text(message='Enter the workspace key backup zip file name')

    if not os.path.exists(backup):
        print('Backupfile: {} not found.'.format(backup))
        exit(- 1)

    
    try:
        privkeys = recover.restore_key_and_chaincode(
            backup, key, passphrase, key_pass, mobile_key, mobile_key_pass)
    except recover.RecoveryErrorMobileKeyDecrypt:
        print(colored("Failed to decrypt mobile Key. " + colored("Please make sure you have the mobile passphrase entered correctly.", attrs = ["bold"]), "cyan"))
        exit(-1)
    except recover.RecoveryErrorRSAKeyImport:
        print(colored("Failed to import RSA Key. " + colored("Please make sure you have the RSA passphrase entered correctly.", attrs = ["bold"]), "cyan"))
        exit(-1)
    except recover.RecoveryErrorMobileRSAKeyImport:
        print(colored("Failed to import mobile RSA Key. " + colored("Please make sure you have the RSA passphrase entered correctly.", attrs = ["bold"]), "cyan"))
        exit(-1)
    except recover.RecoveryErrorMobileRSADecrypt:
        print(colored("Failed to decrypt mobile Key. " + colored("Please make sure you have the mobile private key entered correctly.", attrs = ["bold"]), "cyan"))
        exit(-1)

    for algo, info in privkeys.items():
        # info may be either None or tuple
        print('ECDSA:' if 'ecdsa' in algo.lower() else 'EDDSA:')
        if info:
            print('worksapce keys - ' + colored("Verified!", "green"))
            privkey, chaincode = info
            pub = recover.get_public_key(algo, privkey)
            if show_xprv:
                print('extended private key:  ' + recover.encode_extended_key(algo, privkey, chaincode, False))
            print('extended public key:   ' + recover.encode_extended_key(algo, pub, chaincode, True))
        else:
            print('worksapce keys - ' + colored("Not verified!", "red"))
    print("\n")


def reveal_backup_private_key():
    show_prv = inquirer.confirm(
        colored('Sensitive data warning!', 'yellow', attrs=['bold']) + ' Are you sure you want to proceed to reveal the private backup key?', default=False)
    if show_prv:
        recover_keys(True)


def pop_main_menu():
    return inquirer.list_input(message=colored(
        "What do you want to do?", "green"),
        choices=menu_options.values(),
    )


def main():

    print(colored("\nWelcome to the Fireblocks backup and recovery tool\n", "cyan"))
    cont = True

    while cont:
        menu_option = pop_main_menu()
        if menu_option == menu_options[CREATE_RECOVERY_KEY_PAIR]:
            create_rsa_key_pair()
        elif menu_option == menu_options[VERIFY_PUBLIC_KEY]:
            verify_public_key()
        elif menu_option == menu_options[VERIFY_RECOVERY_PACKAGE]:
            recover_keys()
        elif menu_option == menu_options[REVEAL_PRV_BACKUP_KEY]:
            reveal_backup_private_key()
        elif menu_option == menu_options[EXIT_MENU]:
            cont = False
        else:
            print(colored('Not a valid choise', 'red'))
            exit(-1)

    print(colored('Goodbye', 'yellow'))

if __name__ == "__main__" :
    main()
