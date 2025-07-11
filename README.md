# Secure P2P Messenger - README
# Overview
Secure P2P Messenger is an encrypted peer-to-peer communication tool that allows users to securely exchange text messages and files using either DES (56-bit) or AES (128-bit) encryption. Developed for SEED Labs, this application demonstrates core security concepts while providing a functional GUI-based messaging system.

# Features
  - End-to-End Encryption: Choose between DES or AES encryption
  - Multiple Message Types:
    - Encrypted text messages
    - Encrypted file transfers (any file type)
  - Visual Cryptography: See ciphertext snippets in chat
  - Cross-Platform: Works on Windows, macOS, and Linux
  - Simple GUI: Built with Tkinter for easy interaction
  - Connection Status: Visual indicators for connection state

# Requirements
Environment
  - SEED Ubuntu 20.04 Lab Environment
  - Python 3.6+
  - tkinter
  - pycryptodome
  - VLC
Dependencies
  - tkinter
  - pycryptodome
  - vlc (for video playing)

# Setup Instructions
1. Prepare SEED Lab Environment
   a. Install the SEED Ubuntu 20.04 VM
   b. Update the system: _sudo apt update_

2. Install Required Packages
  a. Install tkinter: _sudo apt install python3-tk_
  b. Install pycryptodome (if not done): _pip3 install pycryptodome_
  c. Install VLC
    _sudo apt-get install ubuntu-restricted-extra_
    _sudo apt-get install vlc_

3. Prepare Files with in SEED environment
  a. Create a test directory and add sample files:
    mkdir messenger
    cd messenger
  b. Add test files:
    _touch projectTestPhoto.jpg_
    _touch StrawSqueak.mp3_
    _touch projectTestVideo.mp4_

4. Download Application
  a. Copy secure_messenger.py to your SEED Ubuntu environment.

# Running the Application
  _python3 secure_messenger.py_

Connection Setup
Listener Setup (Computer A):
  - Enter password (must match on both ends)
  - Select encryption type (both ends must match)
  - Set IP to 127.0.0.1 (for same-machine testing)
  - Set port (e.g., 12345)
  - Click Listen
Connector Setup (Computer B):
  - Enter same password and encryption type
  - Set IP to listener's IP (127.0.0.1 for local testing)
  - Set same port as listener
  - Click Connect

Sending Messages
Text Messages:
  - Type message in input box
  - Press Enter or click Send
  - Ciphertext snippet appears in chat
Files:
  - Click Send File
  - Select any file type
  - File will be encrypted and transmitted
  - Receiver will be prompted to save
Testing Media Files
  - Send test media files (jpg, mp3, mp4)
  - Receiver saves file when prompted
  - Open saved file with VLC/media player:
    _vlc received_projectTestVideo.mp4_
