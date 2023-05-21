import hashlib
import base64
import qrcode
from PIL import Image

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

    image_file = Image.open("pub_key_qr.png")
    image_file.show()
