import hashlib
import base64
import qrcode
from PIL import Image
import os
import sys
from termcolor import colored

def existingGraphic():
    if sys.platform == 'linux':
        if "DISPLAY" not in os.environ and "WAYLAND_DISPLAY" not in os.environ:
            return False
    return True

def create_short_checksum(key):
    return base64.b64encode(hashlib.sha256(key.encode()).digest())[:8].decode()

def create_and_pop_qr(key):
    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=5)
    qr.add_data(key)
    qr.make(fit=True)

    img = qr.make_image(fill='black', back_color='white')
    img.save('pub_key_qr.png')

    if not existingGraphic():
        print(colored("QR code can't be displayed on this machine. File pub_key_qr.png was saved on your machine", 'yellow', attrs=['bold']))
        return
    image_file = Image.open("pub_key_qr.png")
    image_file.show()
    print(colored(
        "Opened the QR image file for you, and saved it on your machine as pub_key_qr.png.", "cyan"))
