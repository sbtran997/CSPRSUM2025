# Secure P2P Messenger - README
# Overview:
Secure P2P Messenger is a secure instant messaging tool designed for SEED Labs that enables encrypted peer-to-peer communication between Alice and Bob. The system allows users to securely exchange text messages and files (images, audio, video) using either DES (56-bit) or AES (128-bit) encryption. Both parties must share the same password to establish secure communication.

# Features:
  - End-to-End Encryption: Choose between DES or AES encryption
  - Multiple Message Types:
    - Encrypted text messages
    - Encrypted file transfers (any file type)
  - Visual Cryptography: See ciphertext snippets in chat
  - Cross-Platform: Works on Windows, macOS, and Linux
  - Simple GUI: Built with Tkinter for easy interaction
  - Connection Status: Visual indicators for connection state

# Requirements:
Environment and Dependencies
  - SEED Ubuntu 20.04 Lab Environment
  - Python 3.6+
  - tkinter
  - pycryptodome
  - VLC

# Installing Virtual Box with the Seed Labs Environment:
1. Starting off at the Seed Labs Website
   
   a. Start off here: https://seedsecuritylabs.org/labsetup.html
   
   b. Choose Ubuntu 20.04 and follow the steps

3. Download Virtual Box

   a. A link can be found in the VM Manual

4. Download the SEED-Ubuntu20.04.zip file from the SEED website provided earlier

5. Follow the steps provided in the VM Manual from the Seed Lab website or through this link:
   
   a. https://github.com/seed-labs/seed-labs/blob/master/manuals/vm/seedvm-manual.md
   
   b. Make sure to enable Copy and Paste

# Setup Instructions:
1. Prepare SEED Lab Environment

   a. Install the SEED Ubuntu 20.04 VM (If you have not done that already)
   
   b. Update the system:

       sudo apt update

3. Install Required Packages

   a. Install tkinter:

       sudo apt install python3-tk
  
   b. Install pycryptodome (if not done):

       pip3 install pycryptodome
  
   c. Install VLC (Use tab to get through EULA confirmation, also it works if the message "Unable to locate package ubuntu-restricted-extra" appears)
  
       sudo apt-get install ubuntu-restricted-extra
       sudo apt-get install vlc

5. Prepare Files with in SEED environment
   
   a. Create a test directory and add sample files:
  
       mkdir messenger
       cd messenger
    
   b. Add picture, audio, and video test files (You can also download them straight into the VM using pixabay):
  
       touch example.jpg
       touch example.mp3
       touch example.mp4

7. Download Application
   
   a. Copy _secure_messenger.py_ to your SEED Ubuntu environment.

# Running the Application:

1. Local Testing:
   
   a. Once everything is setup in your environment, open up 2 terminals in your VM and run the command:

       python3 secure_messenger.py

2. Connection Setup for Listener (Computer 1)

   a. In your first terminal enter a password that would be used for both "users"
   
   b. Select encryption type (both ends must match)

   c. Set IP to 127.0.0.1 (for same machine testing)

   d. Set the port value (e.g., 12345)

   e. Click Listen

3. Connection Setup for Connector (Computer 2)

   a. In your second terminal enter the same password and encryption type
   
   b. Set IP to listener's IP (127.0.0.1 for local testing)

   c. Set same port as listener

   d. Click Connect

4. Sending Messsages
   
   a. Type a message in the input box

   b. Click Send (Sometimes hidden when the window is small)

   c. Plaintext and Ciphertext outputted for the Connector
   
6. Sending Files
   
   a. Click Send File (Sometimes hidden when the window is small)

   b. Select one of the test files

   c. File will be encrypted and transmitted

   d. Receiver will be prompted to save
   
7. Sending Video Files
   
   a. Send the example video file (.mp4)

   b. Connector saves file when prompted

   c. Open saved file with VLC/media player:

       # Output should be something similar to "vlc received_projectTestVideo.mp4"
   

2. Network Testing:

   a. Very similar steps above, but just use the correct IP addresses and Ports within the application.

   b. Also, 1 terminal for each machine.

# Troubleshooting:

- If connection fails:

  - Check if ports aren't blocked by firewall, are being used by other processes, or try different port numbers
  -     netstat -ano | findstr <port>

  - Verify IP address is correct

  - Ensure listener is running before connecting
 
  - Try restarting both applications

- If messages don't decrypt:

  - Confirm passwords match exactly and 

  - Verify both selected same algorithm

  - Try resetting keys after connection

# Common Mistakes:

- Not using the same "Your Port" on both machines (Local Testing)

- Different passwords/algorithms on each end

- Trying to connect before listener is active

- Using ports already occupied by other applications
