# CSPRSUM2025
Secure P2P Messenger - README
Overview
Secure P2P Messenger is an encrypted peer-to-peer communication tool that allows users to securely exchange text messages and files using either DES (56-bit) or AES (128-bit) encryption. Developed for SEED Labs, this application demonstrates core security concepts while providing a functional GUI-based messaging system.

Features
End-to-End Encryption: Choose between DES or AES encryption

Multiple Message Types:

Encrypted text messages

Encrypted file transfers (any file type)

Visual Cryptography: See ciphertext snippets in chat

Cross-Platform: Works on Windows, macOS, and Linux

Simple GUI: Built with Tkinter for easy interaction

Connection Status: Visual indicators for connection state

Requirements
Environment
SEED Ubuntu 20.04 Lab Environment

Python 3.6+

Desktop environment with GUI support

Dependencies
bash
# Core requirements
sudo apt update
sudo apt install python3-tk python3-pip
pip3 install pycryptodome

# Media playback support (for received files)
sudo apt-get install ubuntu-restricted-extras vlc
Setup Instructions
1. Prepare SEED Lab Environment
Install the SEED Ubuntu 20.04 VM

Update the system:

bash
sudo apt update && sudo apt upgrade -y
2. Install Required Packages
bash
# Install GUI and crypto dependencies
sudo apt install python3-tk python3-pip
pip3 install pycryptodome

# Install media support (accept EULA during installation)
sudo apt-get install ubuntu-restricted-extras vlc
3. Prepare Test Files
Create a test directory and add sample files:

bash
mkdir messenger_test
cd messenger_test
# Add test files (replace with your actual files):
touch projectTestPhoto.jpg
touch StrawSqueak.mp3
touch projectTestVideo.mp4
4. Download Application
Copy secure_messenger.py to your SEED Ubuntu environment.

Usage Instructions
Running the Application
bash
python3 secure_messenger.py
Connection Setup
Listener Setup (Computer A):

Enter password (must match on both ends)

Select encryption type (both ends must match)

Set IP to 127.0.0.1 (for same-machine testing)

Set port (e.g., 12345)

Click Listen

Connector Setup (Computer B):

Enter same password and encryption type

Set IP to listener's IP (127.0.0.1 for local testing)

Set same port as listener

Click Connect

Sending Messages
Text Messages:

Type message in input box

Press Enter or click Send

Ciphertext snippet appears in chat

Files:

Click Send File

Select any file type

File will be encrypted and transmitted

Receiver will be prompted to save

Testing Media Files
Send test media files (jpg, mp3, mp4)

Receiver saves file when prompted

Open saved file with VLC/media player:

bash
vlc received_projectTestVideo.mp4
Security Notes
🔒 Fixed Salt Warning: This implementation uses a fixed salt for key derivation. In production systems, salts should be randomly generated and exchanged securely.

⚠️ DES Security: DES (56-bit) is included for educational purposes but is considered insecure for modern use. Prefer AES (128-bit) for better security.

🔑 Password Strength: Use strong passwords to compensate for the fixed salt implementation.

🔄 Key Management: Keys are derived from passwords each time - no persistent key storage.

Troubleshooting
Connection Issues:

Verify IP addresses and port match

Check firewall settings

Ensure listener is running before connecting

Tkinter Errors:

bash
sudo apt install python3-tk
Media Playback Issues:

bash
sudo apt-get install --reinstall ubuntu-restricted-extras vlc
Encryption Errors:

Ensure both parties use same password

Verify same encryption type selected (DES vs AES)

License
This project is for educational use as part of SEED Labs. Refer to your course materials for distribution permissions.
