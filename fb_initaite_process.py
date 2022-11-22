#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io
import os
import argparse
from termcolor import colored
import inquirer
import qrcode
from PIL import Image
import hashlib
import base64



def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('pub_key', help='Public key file')

    args = parser.parse_args()

    if not os.path.exists(args.pub_key):
        print('Public key file: {} not found.'.format(args.pub_key))
        exit(- 1)

    with open(args.pub_key, 'r') as _pub_key:
        pub_key = _pub_key.read()

    question = [
        inquirer.List('approval_method',
                      message=colored("Do you wish to approve using qr code or checksum", "green"),
                      choices=['QR Code', 'Checksum'],
                      ),
    ]

    answer = inquirer.prompt(question)
    qr_code = True if answer["approval_method"] == 'QR Code' else False

    if qr_code:
        qr = qrcode.QRCode(
            version=1,
            box_size=10,
            border=5)
        qr.add_data(pub_key)
        qr.make(fit=True)

        img = qr.make_image(fill='black', back_color='white')
        img.save('pub_key_qr.png')

        image_file = Image.open("pub_key_qr.png")
        image_file.show()
        print(colored("Opened the qr file for you and saved it on you machine as pub_key_qr.png", "cyan"))
    else:
        print(base64.b64encode(hashlib.sha256(pub_key.encode()).digest())[:8].decode())
        print(colored("here is your checksum: THIS IS CHECKSUM", "cyan"))

if __name__ == "__main__" :
    main()