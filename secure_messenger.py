import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import struct
import os
import time
import binascii

class SecureMessenger:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure P2P Messenger")
        self.root.geometry("600x500")
        
        # GUI Setup
        frame = tk.Frame(root)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Connection panel
        conn_frame = tk.LabelFrame(frame, text="Connection Settings")
        conn_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(conn_frame, text="Password:").grid(row=0, column=0, sticky="w")
        self.password = tk.Entry(conn_frame, show="*", width=30)
        self.password.grid(row=0, column=1, padx=5, pady=2)
        
        tk.Label(conn_frame, text="Key Length:").grid(row=1, column=0, sticky="w")
        self.key_length = tk.StringVar(value="128")
        key_frame = tk.Frame(conn_frame)
        key_frame.grid(row=1, column=1, sticky="w")
        tk.Radiobutton(key_frame, text="56-bit (DES)", variable=self.key_length, value="56").pack(side=tk.LEFT)
        tk.Radiobutton(key_frame, text="128-bit (AES)", variable=self.key_length, value="128").pack(side=tk.LEFT, padx=(10,0))
        
        tk.Label(conn_frame, text="IP:").grid(row=2, column=0, sticky="w")
        self.ip_entry = tk.Entry(conn_frame, width=30)
        self.ip_entry.grid(row=2, column=1, padx=5, pady=2)
        self.ip_entry.insert(0, "127.0.0.1")
        
        tk.Label(conn_frame, text="Port:").grid(row=3, column=0, sticky="w")
        self.port_entry = tk.Entry(conn_frame, width=30)
        self.port_entry.grid(row=3, column=1, padx=5, pady=2)
        self.port_entry.insert(0, "12345")
        
        btn_frame = tk.Frame(conn_frame)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=5)
        self.connect_btn = tk.Button(btn_frame, text="Listen", command=self.start_server)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        self.client_btn = tk.Button(btn_frame, text="Connect", command=self.connect_to_server)
        self.client_btn.pack(side=tk.LEFT, padx=5)
        self.status_label = tk.Label(btn_frame, text="Status: Disconnected", fg="red")
        self.status_label.pack(side=tk.LEFT, padx=10)

        # Chat panel
        chat_frame = tk.LabelFrame(frame, text="Messaging")
        chat_frame.pack(fill=tk.BOTH, expand=True)
        
        self.chat_box = tk.Text(chat_frame, state=tk.DISABLED)
        self.chat_box.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        input_frame = tk.Frame(chat_frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        self.msg_entry = tk.Entry(input_frame)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,5))
        self.msg_entry.bind("<Return>", lambda e: self.send_text())
        self.send_btn = tk.Button(input_frame, text="Send", command=self.send_text)
        self.send_btn.pack(side=tk.LEFT, padx=(0,5))
        self.file_btn = tk.Button(input_frame, text="Send File", command=self.send_file)
        self.file_btn.pack(side=tk.LEFT)
        
        # Connection state
        self.sock = None
        self.connection = None
        self.running = True
        self.connected = False
        self.receive_thread = None
    
    def update_status(self, message, color="black"):
        """Update status label and chat box with timestamped message"""
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        self.status_label.config(text=f"Status: {message}", fg=color)
        self._update_chat(f"[{timestamp}] {message}")
    
    def derive_key(self):
        """Derive encryption key from password"""
        salt = b'fixed_salt_'  # In real system, exchange salt securely
        key_len = int(self.key_length.get())
        return PBKDF2(self.password.get().encode(), salt, dkLen=key_len//8)
    
    def encrypt(self, data):
        """Encrypt data with selected algorithm"""
        key = self.derive_key()
        if self.key_length.get() == "56":
            cipher = DES.new(key, DES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(data, DES.block_size))
            return cipher.iv + ct_bytes
        else:
            cipher = AES.new(key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(data, AES.block_size))
            return cipher.iv + ct_bytes
    
    def decrypt(self, data):
        """Decrypt received data"""
        key = self.derive_key()
        if self.key_length.get() == "56":
            iv, ct = data[:8], data[8:]
            cipher = DES.new(key, DES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), DES.block_size)
        else:
            iv, ct = data[:16], data[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size)
    
    def start_server(self):
        """Start listening socket"""
        if self.receive_thread and self.receive_thread.is_alive():
            return
        self.update_status("Starting server...", "orange")
        threading.Thread(target=self._run_server, daemon=True).start()
    
    def _run_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(('0.0.0.0', int(self.port_entry.get())))
            self.sock.listen(1)
            self.update_status(f"Listening on port {self.port_entry.get()}...", "orange")
            self.connection, addr = self.sock.accept()
            self.connected = True
            self.update_status(f"Connected to {addr[0]}", "green")
            self._receive_messages()
        except Exception as e:
            self.update_status(f"Server error: {str(e)}", "red")
    
    def connect_to_server(self):
        """Connect to remote peer"""
        if self.connected:
            return
        self.update_status("Connecting...", "orange")
        threading.Thread(target=self._connect, daemon=True).start()
    
    def _connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.ip_entry.get(), int(self.port_entry.get())))
            self.connection = self.sock
            self.connected = True
            self.update_status(f"Connected to {self.ip_entry.get()}", "green")
            self._receive_messages()
        except Exception as e:
            self.update_status(f"Connection failed: {str(e)}", "red")
    
    def send_text(self):
        """Send encrypted text message"""
        if not self.connected or not self.connection:
            self.update_status("Not connected!", "red")
            return
            
        msg = self.msg_entry.get()
        if not msg:
            return
            
        try:
            encrypted = self.encrypt(msg.encode())
            # Message format: [TYPE=0x01][LENGTH][DATA]
            header = b'\x01' + struct.pack('!I', len(encrypted))
            self.connection.sendall(header + encrypted)
            
            # ADDED: Show ciphertext in chat
            cipher_hex = binascii.hexlify(encrypted).decode('utf-8')
            short_cipher = cipher_hex[:32] + "..." if len(cipher_hex) > 32 else cipher_hex
            self._update_chat(f"You: {msg}", "blue")
            self._update_chat(f"  [Ciphertext: {short_cipher} ({len(encrypted)} bytes)]", "gray")
            
            self.msg_entry.delete(0, tk.END)
        except Exception as e:
            self.update_status(f"Send error: {str(e)}", "red")
    
    def send_file(self):
        """Send encrypted file"""
        if not self.connected or not self.connection:
            self.update_status("Not connected!", "red")
            return
            
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
            
        try:
            with open(filepath, 'rb') as f:
                file_data = f.read()
            encrypted = self.encrypt(file_data)
            filename = os.path.basename(filepath).encode()
            
            # Message format: [TYPE=0x02][FILENAME_LEN][FILENAME][DATA_LEN][DATA]
            header = b'\x02' + struct.pack('!I', len(filename)) + filename
            header += struct.pack('!I', len(encrypted))
            
            self.connection.sendall(header + encrypted)
            
            # ADDED: Show ciphertext in chat
            cipher_hex = binascii.hexlify(encrypted).decode('utf-8')
            short_cipher = cipher_hex[:32] + "..." if len(cipher_hex) > 32 else cipher_hex
            self._update_chat(f"Sent file: {filename.decode()}", "darkgreen")
            self._update_chat(f"  [Ciphertext: {short_cipher} ({len(encrypted)} bytes)]", "gray")
        except Exception as e:
            self.update_status(f"File send failed: {str(e)}", "red")
    
    def _receive_messages(self):
        self.receive_thread = threading.current_thread()
        while self.running and self.connected:
            try:
                # Read message type (1 byte)
                msg_type = self.connection.recv(1)
                if not msg_type:
                    self.update_status("Connection closed by peer", "red")
                    self.connected = False
                    break
                    
                # TEXT MESSAGE (0x01)
                if msg_type == b'\x01':
                    # Read message length
                    len_header = self.connection.recv(4)
                    if not len_header:
                        break
                    msg_len = struct.unpack('!I', len_header)[0]
                    
                    # Receive message data
                    data = b''
                    while len(data) < msg_len:
                        chunk = self.connection.recv(min(4096, msg_len - len(data)))
                        if not chunk:
                            break
                        data += chunk
                    
                    if len(data) != msg_len:
                        self.update_status("Incomplete text message received", "orange")
                        continue
                    
                    try:
                        decrypted = self.decrypt(data)
                        plaintext = decrypted.decode()
                        
                        # ADDED: Show ciphertext in chat
                        cipher_hex = binascii.hexlify(data).decode('utf-8')
                        short_cipher = cipher_hex[:32] + "..." if len(cipher_hex) > 32 else cipher_hex
                        self._update_chat(f"Peer: {plaintext}", "purple")
                        self._update_chat(f"  [Ciphertext: {short_cipher} ({len(data)} bytes)]", "gray")
                    except Exception as e:
                        self.update_status(f"Decryption failed: {str(e)}", "red")
                
                # FILE MESSAGE (0x02)
                elif msg_type == b'\x02':
                    # Read filename length
                    fn_len_header = self.connection.recv(4)
                    if not fn_len_header:
                        break
                    fn_len = struct.unpack('!I', fn_len_header)[0]
                    
                    # Read filename
                    filename = self.connection.recv(fn_len)
                    if not filename:
                        break
                    
                    # Read file data length
                    file_len_header = self.connection.recv(4)
                    if not file_len_header:
                        break
                    file_len = struct.unpack('!I', file_len_header)[0]
                    
                    # Receive file data
                    file_data = b''
                    while len(file_data) < file_len:
                        chunk = self.connection.recv(min(4096, file_len - len(file_data)))
                        if not chunk:
                            break
                        file_data += chunk
                    
                    if len(file_data) != file_len:
                        self.update_status("Incomplete file received", "orange")
                        continue
                    
                    try:
                        decrypted = self.decrypt(file_data)
                        self._save_file(filename, decrypted)
                        
                        # ADDED: Show ciphertext in chat
                        cipher_hex = binascii.hexlify(file_data).decode('utf-8')
                        short_cipher = cipher_hex[:32] + "..." if len(cipher_hex) > 32 else cipher_hex
                        self._update_chat(f"  [Ciphertext: {short_cipher} ({len(file_data)} bytes)]", "gray")
                    except Exception as e:
                        self.update_status(f"File decryption failed: {str(e)}", "red")
                
                else:
                    self.update_status(f"Unknown message type: {msg_type}", "orange")
                    
            except ConnectionResetError:
                self.update_status("Connection reset by peer", "red")
                self.connected = False
                break
            except Exception as e:
                self.update_status(f"Receive error: {str(e)}", "red")
                continue
    
    def _save_file(self, filename, data):
        try:
            filename_str = filename.decode(errors='replace')
            save_path = filedialog.asksaveasfilename(
                initialfile=filename_str,
                title="Save received file"
            )
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(data)
                self._update_chat(f"Received file: {filename_str}", "darkmagenta")
        except Exception as e:
            self.update_status(f"File save error: {str(e)}", "red")
    
    def _update_chat(self, message, color="black"):
        self.chat_box.config(state=tk.NORMAL)
        if color not in self.chat_box.tag_names():
            self.chat_box.tag_configure(color, foreground=color)
        self.chat_box.insert(tk.END, message + "\n", color)
        self.chat_box.config(state=tk.DISABLED)
        self.chat_box.yview(tk.END)
    
    def on_closing(self):
        self.running = False
        self.connected = False
        if self.connection:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
            except:
                pass
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureMessenger(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
