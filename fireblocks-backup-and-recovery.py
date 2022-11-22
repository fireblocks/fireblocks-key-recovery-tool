#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from random import choices
from termcolor import colored
import inquirer
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from utils.public_key_verification import create_short_checksum
from utils.public_key_verification import create_and_pop_qr


CREATE_RECOVERY_KEY_PAIR = 'CREATE_RECOVERY_KEY_PAIR'
VERIFY_PUBLIC_KEY = 'VERIFY_PUBLIC_KEY'
EXIT_MENU = 'EXIT_MENU'
DEFAULT_KEY_FILE_PREFIX = 'fb-recovery'
SHORT_PHRASE_VERIFICATION = 'SHORT_PHRASE_VERIFICATION'
QR_CODE_VERIFICATION = 'QR_CODE_VERIFICATION'
KEY_SIZE = 4096
PUBLIC_EXPONENT = 65537


menu_options = {
    CREATE_RECOVERY_KEY_PAIR: '1. Create a recovery key pair',
    VERIFY_PUBLIC_KEY: '2. Verify the public backup key',
    EXIT_MENU: '3. Exit menu'
}


public_key_verification_menu_options = {
    QR_CODE_VERIFICATION: '1. Display a scannable public key QR code',
    SHORT_PHRASE_VERIFICATION: '2. Obtain a public key short phrase',
    EXIT_MENU: '3. Exit menu'
}


def confirm(statement, default_value=False):
    return inquirer.confirm(statement, default=default_value)


def pop_main_menu():
    return inquirer.list_input(message=colored(
        "What do you want to do?", "green"),
        choices=menu_options.values(),
    )


def pop_validate_pub_key_menu():
    return inquirer.list_input(message=colored(
        "Choose the verification method: ", 'green'),
        choices=public_key_verification_menu_options.values(),
    )


def create_rsa_key_pair():
    print(colored('Generating RSA private key, 4096 bit long modulus', 'cyan'))

    passphrase = inquirer.password(
        message='Enter pass phrase for fb-recovery-prv.pem')
    verify_passphrase = inquirer.password(
        message='Verifying - Enter pass phrase for fb-recovery-prv.pem')

    if not passphrase or not verify_passphrase or passphrase != verify_passphrase:
        print(colored('Verifying passphrase failed! Please try again', 'red'))
        exit(-1)

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

    print(colored('Created files with prefix ' + key_prefix, "cyan"))


def verify_public_key():
    print(colored('Verfying public key for backup and recovery', 'cyan'))

    file_path = inquirer.text(
        message="Enter your public key file name or press enter for default", default=DEFAULT_KEY_FILE_PREFIX+'-pub.pem')

    if not os.path.exists(file_path):
        print('Public key file: {} not found.'.format(file_path))
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
            print("The short phrase is: ", colored(
                create_short_checksum(pub_key), "red"))
        elif menu_options == public_key_verification_menu_options[EXIT_MENU]:
            cont=False
        else:
            print(colored('Not a valid choise', 'red'))
            exit(-1)


def main():
    print(colored("\nWelcome to the Fireblocks backup and recovery tool.\n", "cyan"))
    cont = True

    while cont:
        menu_option = pop_main_menu()
        if menu_option == menu_options[CREATE_RECOVERY_KEY_PAIR]:
            create_rsa_key_pair()
        elif menu_option == menu_options[VERIFY_PUBLIC_KEY]:
            verify_public_key()
        elif menu_option == menu_options[EXIT_MENU]:
            cont = False
        else:
            print(colored('Not a valid choise', 'red'))
            exit(-1)


if __name__ == "__main__":
    main()
