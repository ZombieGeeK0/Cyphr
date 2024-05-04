import tkinter as tk
from PIL import Image, ImageTk
from hashlib import md5
from hashlib import sha512
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def save_plain_text():
    global plain_text
    plain_text = text_entry.get()
    response.insert(tk.END, f'[INFO]: Saved plain text: {plain_text}\n', 'blue') 
    text_entry.delete(0, tk.END)

def encrypt_md5():
    encrypted_md5_message = md5(plain_text.encode('utf8')).hexdigest()
    response.insert(tk.END, f'[OUTPUT]: Message encrypted in md5: {encrypted_md5_message}\n', 'red') 

def encrypt_sha512():
    encrypted_sha512_message = sha512(plain_text.encode('utf8')).hexdigest()
    response.insert(tk.END, f'[OUTPUT]: Message encrypted in sha512: {encrypted_sha512_message}\n', 'red') 

def clear():
    response.delete(1.0, tk.END)

def encrypt_base64():
    text_bytes_base64 = plain_text.encode('utf-8')
    encrypted_base64_message = base64.b64encode(text_bytes_base64)
    response.insert(tk.END, f'[OUTPUT]: Message encrypted in base64: {encrypted_base64_message.decode("utf-8")}\n', 'red') 

def encrypt_binary():
    encrypted_binary_message = ' '.join(format(ord(caracter), '08b') for caracter in plain_text)
    response.insert(tk.END, f'[OUTPUT]: Message encrypted to binary: {encrypted_binary_message}\n', 'red') 

def encrypt_rsa():
    public_key = RSA.generate(2048).publickey()
    method = PKCS1_OAEP.new(public_key)
    encrypted_rsa_message = method.encrypt(plain_text.encode())
    response.insert(tk.END, f'[OUTPUT]: Message encrypted with RSA: {encrypted_rsa_message}\n', 'red') 

window = tk.Tk()
window.title("Cyphr")
window.geometry("1200x500")

icon_image = Image.open("image.png")
icon_photo = ImageTk.PhotoImage(icon_image)
window.iconphoto(True, icon_photo)

input_frame = tk.Frame(window)
input_frame.pack(pady=10, padx=10, fill=tk.X)

button_frame = tk.Frame(window)
button_frame.pack(pady=5)

text_entry_label = tk.Label(input_frame, text="Plain text to encrypt: ", font=("Consolas", 12))
text_entry_label.grid(row=0, column=0, padx=(0, 10))

text_entry = tk.Entry(input_frame, width=30, font=("Consolas", 12))
text_entry.grid(row=0, column=1)

save_plain_text_button = tk.Button(input_frame, text="Guardar", font=("Consolas", 12), command=save_plain_text)
save_plain_text_button.grid(row=0, column=2, padx=(10, 0))

md5_button = tk.Button(button_frame, text="Encrypt with md5", font=("Consolas", 12), command=encrypt_md5)
md5_button.pack(side=tk.LEFT, padx=5)

sha512_button = tk.Button(button_frame, text="Encrypt with sha512", font=("Consolas", 12), command=encrypt_sha512)
sha512_button.pack(side=tk.LEFT, padx=5)

base64_button = tk.Button(button_frame, text="Encrypt with base64", font=("Consolas", 12), command=encrypt_base64)
base64_button.pack(side=tk.LEFT, padx=5)

binary_button = tk.Button(button_frame, text="Encrypt to binary", font=("Consolas", 12), command=encrypt_binary)
binary_button.pack(side=tk.LEFT, padx=5)

clear_button = tk.Button(button_frame, text="Clear output screen", font=("Consolas", 12), command=clear)
clear_button.pack(side=tk.LEFT, padx=5)

rsa_button = tk.Button(button_frame, text="Encrypt with RSA", font=("Consolas", 12), command=encrypt_rsa)
rsa_button.pack(side=tk.LEFT, padx=5)

response = tk.Text(window, font=("Consolas", 12))
response.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

response.tag_configure('blue', foreground='blue')
response.tag_configure('red', foreground='red')

window.mainloop()
