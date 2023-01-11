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


def write_out(mfa_data):

    if not os.path.isdir('export'):
        os.makedirs('export')

    with open('export/export.json', 'w') as f:
        f.write(json.dumps(mfa_data))

    table = "<table>\n"
    table += "  <tr>\n"
    table += "    <th>Issuer</th>\n"
    table += "    <th>Account</th>\n"
    table += "    <th>QR</th>\n"
    table += "  </tr>\n"


    for account in mfa_data['accounts']:
        totp = pyotp.TOTP(account['secret'].replace(' ', ''))

        uri = totp.provisioning_uri(
            name = account['userName'],
            issuer_name = account['issuerName']
        )

        img = qrcode.make(uri)
        img.save(f'export/{account["accountID"]}.png')

        table += "  <tr>\n"
        table += f"    <td>{account['issuerName']}</td>\n"
        table += f"    <td>{account['userName']}</td>\n"
        table += f"    <td><img src='{account['accountID']}.png' width='200' height='200'></td>\n"
        table += f"  </tr>\n"

    table += "</table>"

    with open('export/export.html', 'w') as f:
        f.write(table)


def get_args():
    parser = argparse.ArgumentParser(description='Export LastPass authenticator QR Codes.')
    parser.add_argument('-s', '--sourcedir', help='Source Directory', required=True)
    parser.add_argument('-o', '--destdir', help='Destination Directory', required=False)

    return parser.parse_args()


def main():

    args = get_args()
    sourcedir = args.sourcedir
    destdir = args.destdir
    print("Please enter otp URL")
    totpinput = getpass.getpass()

    # Parse the url, checking for errors.
    try:
        totp = pyotp.parse_uri(totpinput)
    except Exception as error:
        print("The OTP URL entered is incorrect", error)
        exit
    # Below are the attributes for the otp object
    #['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', 'at', 'byte_secret', 'digest', 'digits', 'generate_otp', 'int_to_bytestring', 'interval', 'issuer', 'name', 'now', 'provisioning_uri', 'secret', 'timecode', 'verify']

    exit
    # Check that the directory exists and that the file exists
    # Read the export file
    fullpath =os.path.join(sourcedir, 'export.json')
    if path.exists(fullpath):
        with open(fullpath, 'r') as plaintext:
            mfa_data = json.loads(plaintext.read())
    else:
        print("The path " + fullpath + " does not exist")
        exit
    # Determine if the item already exists (based on Issuer and list the usernames for selection)
    foundissuer=False
    accounts = []
    for account in mfa_data['accounts']:
        if (account['issuerName'] == totp.issuer):
            foundissuer=True
            accounts.append(account)
           
    if foundissuer:
        print("Issuer found")  
    else:
        print("Issuer not found")
    exit
    # If it does, prompt with selection of username or option to create new
    # If users select update, update the appropriat entry
    # Otherwise if item does not or user selects create new, add it
    # Back up current export file
    # Write out data to export file
    # Then call write_out
    write_out(mfa_data)


if __name__ == '__main__':
    main()
