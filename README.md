## Secure File Encryption Tool 🔐

A simple Python command-line tool for securely encrypting and decrypting files using a password.
It uses PBKDF2 key derivation and Fernet symmetric encryption from the cryptography library to ensure strong security.

## Features

Password-based file encryption
Secure key derivation with PBKDF2 (SHA-256, 100,000 iterations)
Random salt generated for every encryption
Safe decryption with password verification
Logs encryption and decryption activity
Simple command-line interface

## Requirements

Python 3.7+
cryptography library

## Install the required dependency:

pip install cryptography

## How It Works

You provide a password.
A random 16-byte salt is generated.
A secure encryption key is derived using PBKDF2.
The file is encrypted using Fernet.
The encrypted file is saved with a .enc extension.
The salt is stored at the beginning of the encrypted file for later decryption.

Usage

## Run the script:

python encryption_tool.py

## You will see a menu:
Secure File Encryption Tool
1. Encrypt File
2. Decrypt File

## Encrypt a File

Choose option 1
Enter the filename (example: document.txt)
Enter a password when prompted
Output: document.txt.enc

## Decrypt a File

Choose option 2
Enter the encrypted filename (example: document.txt.enc)
Enter the correct password
Output: document.txt.dec


## Logging
All encryption and decryption attempts are logged in:
encryption.log

## This includes:

Successful encryptions
Successful decryptions
Failed decryption attempts (wrong password or corrupted file)

## Security Notes ⚠️

Do not lose your password — encrypted files cannot be recovered without it.
Each encryption uses a unique salt, improving security.

This tool is intended for personal or educational use.

Always keep backups of important files before encrypting.
