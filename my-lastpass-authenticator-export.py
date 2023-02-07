#!/usr/bin/env python3

import requests
import binascii
import hashlib
import base64
import json
import os
import os.path
import pyotp
import qrcode
import argparse
import getpass
import glob
import cv2
import pathlib
from PIL import Image
from pyzbar import pyzbar



from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from os import path

VERIFY = True
USER_AGENT = 'lastpass-python/{}'.format('0.3.2')
CLIENT_ID = 'LastPassAuthExport'

def iterations(username):

    url = 'https://lastpass.com/iterations.php'
    params = {
        'email': username
    }
    headers = {
        'user-agent': USER_AGENT
    }

    r = requests.get(
        url = url,
        params = params,
        verify = VERIFY,
        headers = headers
    )

    try:
        iterations = int(r.text)
    except ValueError:
        iterations = 5000
        
    return iterations


def create_hash(username, password, iteration_count):
    
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), username.encode('utf-8'), iteration_count, 32)
    
    login_hash = binascii.hexlify(
        hashlib.pbkdf2_hmac('sha256', key, password.encode('utf-8'), 1, 32)
    )

    return key, login_hash


def login(username, password, otp=None):

    session = requests.Session()
    session.headers = {'user-agent': USER_AGENT}
    url = 'https://lastpass.com/login.php'
    iteration_count = iterations(username)
    key, login_hash = create_hash(username, password, iteration_count)

    data = {
        'method': 'mobile',
        'web': 1,
        'xml': 1,
        'username': username,
        'hash': login_hash,
        'iterations': iteration_count,
        'imei': CLIENT_ID
    }

    if otp:
        data.update({'otp': otp})

    r = session.post(
        url = url,
        data = data,
        verify = VERIFY
    )

    if not r.text.startswith('<ok'):
        print('Login failed!')
        print(r.text)
        exit(1)
    else:
        csrf = session.post('https://lastpass.com/getCSRFToken.php', verify=VERIFY).text
        return r.cookies.get_dict()['PHPSESSID'], csrf, key



def get_mfa_backup(session, csrf):

    url = 'https://lastpass.com/lmiapi/authenticator/backup'

    headers = {
        'X-CSRF-TOKEN': csrf,
        'X-SESSION-ID': session,
        'user-agent': USER_AGENT
    }

    r = requests.get(
        url = url,
        headers = headers,
        verify = VERIFY
    )

    return r.json()['userData']


def decrypt_user_data(user_data, key):

    data_parts = user_data.split('|')
    iv = base64.b64decode(data_parts[0].split('!')[1])
    ciphertext = base64.b64decode(data_parts[1])

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    )
    mfa_data = json.loads(plaintext)
    
    return mfa_data


def write_out(totp, uri, destdir):

 
    img = qrcode.make(uri)
    name = totp.name.replace(":", "")
    try:
        img.save(f"{destdir}/{totp.issuer} - {name}.png")
        print(f"Created image {destdir}/{totp.issuer} - {name}.png")
    except Exception as error:
        print("Problem creating image")

def get_args():
    parser = argparse.ArgumentParser(description='Export LastPass authenticator QR Codes.')
    parser.add_argument('-d', '--destdir', help='Destination Directory', required=True)
    parser.add_argument('-i', '--qrimage', help='QR image file', required=False)

    return parser.parse_args()

def read_qr_code(filename):
    """Read an image and read the QR code.
    
    Args:
        filename (string): Path to file
    
    Returns:
        qr (string): Value from QR code
    """
    
    try:
        img = cv2.imread(filename)
        detect = cv2.QRCodeDetector()
        value, points, straight_qrcode = detect.detectAndDecode(img)
        if value == "":
            img = Image.open(filename)
            list = pyzbar.decode(img)
            value = list[0].data
        return value
    except Exception as error:
        print("Error", error)
        return

def main():

    args = get_args()
 
    destdir = args.destdir
    if args.qrimage is None:
        print("Please enter otp URL")
        totpinput = getpass.getpass()
    else:
        my_file = pathlib.Path(args.qrimage)
        if my_file.is_file():
            totpinput = read_qr_code(args.qrimage)
        else:
            print(args.qrimage + " is not a valid file")
            os._exit(1)
        
    try:
        

        totp = pyotp.parse_uri(totpinput)
        if totp.issuer in totp.name:
            print("Issuer is in name")
        else:
            print("Issuer is *not* in name.  Revising")
            totpinput=totpinput.replace(totp.name + "?", totp.issuer + ":" + totp.name + "?")
            #totp.name=totp.issuer + ":" + totp.name
            #print(totp.name)
            totp = pyotp.parse_uri(totpinput)
    except Exception as error:
        print("The OTP URL entered is incorrect", error)
        os._exit(1)

    write_out(totp, totpinput, destdir)


if __name__ == '__main__':
    main()
