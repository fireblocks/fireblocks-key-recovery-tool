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


pubkey_descriptions = {
    'MPC_ECDSA_SECP256K1': 'MPC_ECDSA_SECP256K1 XPUB',
    'MPC_CMP_ECDSA_SECP256K1': 'MPC_ECDSA_SECP256K1 XPUB',
    'MPC_EDDSA_ED25519': 'MPC_EdDSA_ED25519 extended public key (Fireblocks format)',
    'MPC_CMP_EDDSA_ED25519': 'MPC_EdDSA_ED25519 extended public key (Fireblocks format)',
}


privkey_descriptions = {
    'MPC_ECDSA_SECP256K1': 'MPC_ECDSA_SECP256K1 XPRV',
    'MPC_CMP_ECDSA_SECP256K1': 'MPC_ECDSA_SECP256K1 XPRV',
    'MPC_EDDSA_ED25519': 'MPC_EdDSA_ED25519 extended private key (Fireblocks format)',
    'MPC_CMP_EDDSA_ED25519': 'MPC_EdDSA_ED25519 extended private key (Fireblocks format)',
}


menu_options = {
    CREATE_RECOVERY_KEY_PAIR: '1. Create a recovery key pair',
    VERIFY_PUBLIC_KEY: '2. Verify the public backup key',
    VERIFY_RECOVERY_PACKAGE: '3. Verify the recovery package',
    REVEAL_PRV_BACKUP_KEY: '4. Reveal the private backup key',
    EXIT_MENU: '5. Exit menu'
}


public_key_verification_menu_options = {
    QR_CODE_VERIFICATION: '1. Display a scannable public key QR code',
    SHORT_PHRASE_VERIFICATION: '2. Obtain a public key short phrase',
    EXIT_MENU: '3. Exit menu'
}


def create_rsa_key_pair():
    print(colored('Generating RSA private key, 4096 bit long modulus', 'cyan'))

    passphrase = inquirer.password(
        message='Enter passphrase for the private key')
    verify_passphrase = inquirer.password(
        message=colored('Verifying', 'yellow') + ' - Enter passphrase for the private key')

    if not passphrase or not verify_passphrase or passphrase != verify_passphrase:
        print(colored('\nVerifying passphrase failed! Please try again', 'red'))
        return

    print('\nThis mighr take a few seconds...')

    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE
    )

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

    key_prefix = inquirer.text(
        message="Enter your public key file name or press enter for default", default=DEFAULT_KEY_FILE_PREFIX)

    private_key_file = open(key_prefix + '-prv.pem', 'w')
    private_key_file.write(encrypted_pem_private_key.decode())
    private_key_file.close()

    public_key_file = open(key_prefix + '-pub.pem', 'w')
    public_key_file.write(pem_public_key.decode())
    public_key_file.close()

    print(colored('\nCreated files with prefix ' + key_prefix, "cyan"))


def pop_validate_pub_key_menu():
    print('\n')
    return inquirer.list_input(message=colored(
        "Choose the verification method: ", 'green'),
        choices=public_key_verification_menu_options.values(),
    )


def verify_public_key():
    print(colored('Verfying public key for backup and recovery', 'cyan'))

    file_path = inquirer.text(
        message="Enter your public key file name or press enter for default", default=DEFAULT_KEY_FILE_PREFIX+'-pub.pem')

    if not os.path.exists(file_path):
        print(colored('Public key file: {} not found.'.format(file_path), "red", attrs=['bold']))
        exit(-1)

    with open(file_path, 'r') as _pub_key:
        pub_key = _pub_key.read()

    cont = True
    while cont:
        menu_options = pop_validate_pub_key_menu()
        if menu_options == public_key_verification_menu_options[QR_CODE_VERIFICATION]:
            create_and_pop_qr(pub_key)
            print(colored(
                "Opened the qr file for you and saved it on you machine as pub_key_qr.png", "cyan"))
        elif menu_options == public_key_verification_menu_options[SHORT_PHRASE_VERIFICATION]:
            print("The short phrase is: " + colored(create_short_checksum(pub_key), attrs=['bold']))
        elif menu_options == public_key_verification_menu_options[EXIT_MENU]:
            cont=False
        else:
            print(colored('Not a valid choise', 'red', attrs=['bold']))
            exit(-1)


def get_recover_keys_args():
    questions = [
        inquirer.Text('backup', message='Enter the backup zip file name'),
        inquirer.Text('key', message='Enter the rsa private key file name'),
        inquirer.Text('mobile_key', message=colored('Optional', attrs=['bold']) + ' Enter the mobile RSA private key file or press enter'),
    ]

    return inquirer.prompt(questions)


def recover_keys(show_xprv=False):
    args = get_recover_keys_args()

    if not os.path.exists(args["backup"]):
        print('Backupfile: {} not found.'.format(args["backup"]))
        exit(- 1)
    if not os.path.exists(args["key"]):
        print('RSA key: {} not found.'.format(args["key"]))
        exit(-1)

    mobile_key_pass = None
    passphrase = None

    if args["mobile_key"] is None:
        passphrase = getpass.getpass(prompt='Please enter mobile recovery passphrase:')
    else:
        with open(args["mobile_key"], 'r') as _key:
            key_file = _key.readlines()
            if 'ENCRYPTED' in key_file[0] or 'ENCRYPTED' in key_file[1]:
                mobile_key_pass = getpass.getpass(prompt='Please enter mobile recovery RSA private key passphrase:')

    with open(args["key"], 'r') as _key:
        key_file = _key.readlines()
        if 'ENCRYPTED' in key_file[0] or 'ENCRYPTED' in key_file[1]:
            key_pass = getpass.getpass(prompt='Please enter recovery RSA private key passphrase:')
        else:
            key_pass = None

    try:
        privkeys = recover.restore_key_and_chaincode(
            args["backup"], args["key"], passphrase, key_pass, args["mobile_key"], mobile_key_pass)
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
        if info:
            privkey, chaincode = info
            pub = recover.get_public_key(algo, privkey)
            if show_xprv:
                print(privkey_descriptions[algo] + ":\t" + recover.encode_extended_key(algo, privkey, chaincode, False))
            print(pubkey_descriptions[algo] + ":\t%s\t%s" % (recover.encode_extended_key(algo, pub, chaincode, True), colored("Verified!","green")))
        else:
            print(pubkey_descriptions[algo] + ":\t%s" % (colored("Verification failed","red")))


def reveal_backup_private_key():
    show_prv = inquirer.confirm(colored(
        colored('Warning', attrs=['bold']) + ' This will reveal your private key. Make sure no one else can see your screen. Continue?', 'yellow'), default=False)
    if show_prv:
        recover_keys(True)


def pop_main_menu():
    print('\n')
    return inquirer.list_input(message=colored(
        "What do you want to do?", "green"),
        choices=menu_options.values(),
    )


def main():

    print(colored("\nWelcome to the Fireblocks backup and recovery tool.\n", "cyan"))
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
