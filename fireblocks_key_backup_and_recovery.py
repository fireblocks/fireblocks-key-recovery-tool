#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from utils import recover
from termcolor import colored
import questionary
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
GO_BACK = 'GO_BACK'
ECDSA = 'ECDSA'
EDDSA = 'EDDSA'

DEFAULT_KEY_FILE_PREFIX = 'fb-recovery'

SHORT_PHRASE_VERIFICATION = 'SHORT_PHRASE_VERIFICATION'
QR_CODE_VERIFICATION = 'QR_CODE_VERIFICATION'

KEY_SIZE = 4096
PUBLIC_EXPONENT = 65537

algorithms = {
    ECDSA: 'ECDSA (used for signing transactions for most blockchains supported by Fireb`locks)',
    EDDSA: 'EDDSA (used for signing transactions for Algorand, Cardano, Polkadot, Solana, Stellar and Ripple blockchains)'
}

menu_options = {
    CREATE_RECOVERY_KEY_PAIR: 'Create a recovery key pair',
    VERIFY_PUBLIC_KEY: 'Verify the public recovery key (for a key backup initiated via Fireblocks Console)',
    VERIFY_RECOVERY_PACKAGE: 'Verify the key backup package',
    REVEAL_PRV_BACKUP_KEY: 'Reveal the private workspace keys',
    EXIT_MENU: 'Exit'
}


public_key_verification_menu_options = {
    QR_CODE_VERIFICATION: 'Display a scannable public key QR code',
    SHORT_PHRASE_VERIFICATION: 'Display a public key short phrase',
    GO_BACK: 'Go back to main menu'
}


def create_rsa_key_pair():
    print("""You are about to create a public and private recovery key
The private recovery key will be encrypted with a passphrase that you choose.""")

    change_file_name = questionary.confirm(
        'The key files are named "fb-recovery-public.pem" and "fb-recovery-private.pem" by default. Do you want to change these names?', 
        default=False
        ).ask()
    if change_file_name:
        key_prefix = questionary.text(
            'Enter a name for your recovery key files. The file names will be suffixed with "-public.pem" and "-private.pem", respectively.'
            ).ask()
    else:
        key_prefix = DEFAULT_KEY_FILE_PREFIX

    passphrase = questionary.password(
        message='Choose a private recovery key passphrase that you will remember.',
        validate=lambda password: True if len(password) > 0 else "Please enter a value"
        ).ask()
    questionary.password(
        message='Confirm the passphrase.',
        validate=lambda password: True if (len(password) > 0 and password == passphrase) else 'Passphrase not verified'
        ).ask()

    public_key_file_name = key_prefix + '-public.pem'
    private_key_file_name = key_prefix + '-private.pem'

    print('\nPublic key file name: {}'.format(public_key_file_name))
    print('Private key file name: {}'.format(private_key_file_name))

    if(os.path.exists(public_key_file_name) or os.path.exists(private_key_file_name)):
        print(colored("\nPublic or private key files with this name already exists.", 'red', attrs=['bold']))
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

    print('The recovery key pair was created. Press Enter to to return to the main menu.')
    input()

def pop_validate_pub_key_menu():
    print('\n')
    return questionary.select(
        'Choose the verification method: ',
        choices=public_key_verification_menu_options.values()
    ).ask()

def is_pem_public_key(key_str):
    try:
        serialization.load_pem_public_key(key_str.encode())
        return True
    except (ValueError, TypeError, AttributeError):
        return False
    
def verify_public_key():
    print('Workspace admins can approve the key backup using the Fireblocks mobile app.\n')

    file_path = questionary.path(
        message='Enter the public recovery key file name or press Enter to use the default name.', 
    ).ask()

    if file_path == '':
        file_path = DEFAULT_KEY_FILE_PREFIX + '-public.pem'

    if not os.path.exists(file_path):
        print(colored('\nPublic key file: {} not found.\n'.format(file_path), 'red', attrs=['bold']))
        return

    with open(file_path, 'r') as _pub_key:
        pub_key = _pub_key.read()
    
    if not is_pem_public_key(pub_key):
        print(colored('\nPublic key file: {} is not a valid PEM public key.\n'.format(file_path), 'red', attrs=['bold']))
        return

    print('\nFound public recovery key file: {}'.format(file_path))
    cont = True
    while cont:
        menu_options = pop_validate_pub_key_menu()
        if menu_options == public_key_verification_menu_options[QR_CODE_VERIFICATION]:
            create_and_pop_qr(pub_key)
            print(colored(
                "Opened the QR image file for you (local run only), and saved it on your machine as pub_key_qr.png.", "cyan"))
        elif menu_options == public_key_verification_menu_options[SHORT_PHRASE_VERIFICATION]:
            print(colored("The public key short phrase is: " + colored(create_short_checksum(pub_key), attrs=['bold']), "cyan"))
            print("Press 'Enter' to continue...")
            input()
        elif menu_options == public_key_verification_menu_options[GO_BACK]:
            cont=False
        else:
            print(colored('Not a valid choise.', 'red', attrs=['bold']))
            return


def recover_keys(show_xprv=False):
    backup = questionary.path(
        message='Enter the key backup package (zip) file name.'
    ).ask()
    if not os.path.exists(backup):
        print('Backupfile: {} not found.'.format(backup))
        return
    
    key = questionary.path(
        message='Enter the private recovery key file name or press Enter to use the default name.', 
    ).ask()

    if key == '':
        key = DEFAULT_KEY_FILE_PREFIX + '-private.pem'

    if not os.path.exists(key):
        print('File not found - {}.'.format(key))
        return

    with open(key, 'r') as _key:
        key_file = _key.readlines()
        if 'ENCRYPTED' in key_file[0] or 'ENCRYPTED' in key_file[1]:
            key_pass = questionary.password(
                message='Enter your private recovery key passphrase.'
            ).ask()
        else:
            key_pass = None

    is_self_drs = questionary.confirm(
        message="Are you using an auto-generated passphrase? (This is not a default feature).", 
        default=False
    ).ask()
    mobile_key = None
    mobile_key_pass = None
    passphrase = None

    if not is_self_drs:
        passphrase = questionary.password(
            message='Enter the recovery passphrase of the workspace owner:'
        ).ask()
    else:
        mobile_key = questionary.path(
            message='Enter the private key file name that you used for your auto-generated passphrase.'
        ).ask()
        if not os.path.exists(mobile_key):
            print('File not found - {}.'.format(mobile_key))
            return
        with open(mobile_key, 'r') as _key:
            key_file = _key.readlines()
            if 'ENCRYPTED' in key_file[0] or 'ENCRYPTED' in key_file[1]:
                mobile_key_pass = questionary.password(
                    message='Enter the passphrase for the private key file.'
                ).ask()


    try:
        privkeys = recover.restore_key_and_chaincode(
            backup, key, passphrase, key_pass, mobile_key, mobile_key_pass)
    except:
        print(colored("""\nCould not open the key backup package. 
Please make sure you have the private key file, the passphrase to the private key file, 
and the passphrase to the owner key share, all entered correctly.\n""", 'red', attrs=['bold']))
        return


    for algo, info in privkeys.items():
        # info may be either None or tuple
        print(algorithms[ECDSA] if 'ecdsa' in algo.lower() else algorithms[EDDSA])
        if info:
            print('worksapce keys - ' + colored("Verified!", "green"))
            privkey, chaincode = info
            pub = recover.get_public_key(algo, privkey)
            if show_xprv:
                print('extended private key -  ' + recover.encode_extended_key(algo, privkey, chaincode, False))
            print('extended public key -   ' + recover.encode_extended_key(algo, pub, chaincode, True))
        else:
            print('worksapce keys - ' + colored("Not verified!", "red"))
    print("\n")


def reveal_backup_private_key():
    print(colored('Sensitive data warning!', 'yellow', attrs=['bold']))
    
    show_prv = questionary.confirm(
        message="Are you sure you want to proceed to reveal the private backup key?",
        default=False
    ).ask()
    if show_prv:
        recover_keys(True)


def pop_main_menu():
    return questionary.select(
        message="What do you want to do?",
        choices=menu_options.values(),
    ).ask()


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
