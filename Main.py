import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import random
import string
import os

# Function to generate a secure key for encryption
def generate_key():
    return Fernet.generate_key()

# Function to save the key to a file
def save_key(key):
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Function to load the key from the file
def load_key():
    if os.path.exists("secret.key"):
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    else:
        # If the key doesn't exist, generate and save a new key
        new_key = generate_key()
        save_key(new_key)
        return new_key

# Function to encrypt the password
def encrypt_password(password, key):
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password

# Function to decrypt the password
def decrypt_password(encrypted_password, key):
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    return decrypted_password

# Function to save the password into a file
def save_password():
    account_name = account_entry.get()
    password = password_entry.get()

    if not account_name or not password:
        messagebox.showerror("Error", "Please fill in both fields.")
        return

    encrypted_password = encrypt_password(password, key)

    with open("passwords.txt", "a") as file:
        file.write(f"Account: {account_name} | Password: {encrypted_password.decode()}\n")

    messagebox.showinfo("Success", f"Password for {account_name} saved successfully!")
    account_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

# Function to load the passwords and decrypt them
def load_passwords():
    try:
        with open("passwords.txt", "r") as file:
            passwords = file.readlines()
            if passwords:
                display_passwords(passwords)
            else:
                messagebox.showinfo("Info", "No passwords found.")
    except FileNotFoundError:
        messagebox.showerror("Error", "No passwords saved yet.")

# Function to display passwords in the text box
def display_passwords(passwords):
    text_box.delete(1.0, tk.END)  # Clear the text box before displaying new passwords
    for password in passwords:
        try:
            # Ensure proper splitting of the account name and password
            account, encrypted_password = password.strip().split(" | ")
            account_name = account.split(": ")[1]
            encrypted_password = encrypted_password.split(": ")[1].strip()

            # Decrypt the password
            decrypted_password = decrypt_password(encrypted_password.encode(), key)
            text_box.insert(tk.END, f"Account: {account_name} | Password: {decrypted_password}\n")
        except Exception as e:
            print(f"Error displaying password: {e}")
            messagebox.showerror("Error", f"Failed to load password: {e}")

# Function to generate and display a strong password
def show_generated_password():
    generated_password = generate_strong_password()
    generated_password_label.config(text=f"Generated Password: {generated_password}")
    password_entry.delete(0, tk.END)  # Clear the current entry
    password_entry.insert(0, generated_password)  # Insert the generated password

# Function to generate a strong random password (letters and digits only)
def generate_strong_password(length=16):
    characters = string.ascii_letters + string.digits  # Only letters and digits
    password = ''.join(random.choice(characters) for i in range(length))
    return password

# Create the main window
window = tk.Tk()
window.title("Password Manager")
window.geometry("600x500")
window.config(bg="#404040")  # Dark gray theme background

# Dark theme styling
font_style = ("Helvetica", 14)
button_style = {"font": ("Helvetica", 12), "bg": "#B0B0B0", "fg": "#212121", "width": 20, "height": 2, "bd": 2, "relief": "solid"}

# Load the key for encryption
key = load_key()

# UI Elements for the main page

def go_to_accounts_page():
    main_page.pack_forget()
    accounts_page.pack()

def go_to_main_page():
    accounts_page.pack_forget()
    main_page.pack()

# Main Page UI
main_page = tk.Frame(window, bg="#404040")  # Set background to gray

# Title label
title_label = tk.Label(main_page, text="Password Manager", font=("Helvetica", 18), fg="#B0B0B0", bg="#404040")
title_label.pack(pady=20)

# Account name label and input
account_label = tk.Label(main_page, text="Account Name:", font=font_style, fg="#B0B0B0", bg="#404040")
account_label.pack(pady=5)

account_entry = tk.Entry(main_page, font=font_style, width=30, bg="#404040", fg="#B0B0B0", bd=2, relief="solid")
account_entry.pack(pady=10)

# Password label and input
password_label = tk.Label(main_page, text="Password:", font=font_style, fg="#B0B0B0", bg="#404040")
password_label.pack(pady=5)

password_entry = tk.Entry(main_page, font=font_style, width=30, bg="#404040", fg="#B0B0B0", bd=2, relief="solid")
password_entry.pack(pady=10)

# Button to save password
save_button = tk.Button(main_page, text="Save Password", command=save_password, **button_style)
save_button.pack(pady=10)

# Button to generate and display a strong password
generate_button = tk.Button(main_page, text="Generate Strong Password", command=show_generated_password, **button_style)
generate_button.pack(pady=10)

# Label to display the generated password
generated_password_label = tk.Label(main_page, text="Generated Password: ", font=font_style, fg="#B0B0B0", bg="#404040")
generated_password_label.pack(pady=10)

# Button to load and display stored passwords
accounts_button = tk.Button(main_page, text="Show Accounts", command=go_to_accounts_page, **button_style)
accounts_button.pack(pady=10)

main_page.pack()

# Accounts Page UI
accounts_page = tk.Frame(window, bg="#404040")  # Set background to gray

# Button to go back to the main page
back_button = tk.Button(accounts_page, text="Back", command=go_to_main_page, **button_style)
back_button.pack(pady=20)

# Text box to display stored passwords
text_box_label = tk.Label(accounts_page, text="Stored Passwords", font=("Helvetica", 16), fg="#B0B0B0", bg="#404040")
text_box_label.pack(pady=20)

# Create the text box and scrollbar
text_box = tk.Text(accounts_page, width=50, height=10, font=("Helvetica", 12), bg="#404040", fg="#B0B0B0", bd=2, relief="solid")
scrollbar = tk.Scrollbar(accounts_page, orient="vertical", command=text_box.yview)
text_box.config(yscrollcommand=scrollbar.set)

# Pack the text box and scrollbar
text_box.pack(pady=10)
scrollbar.pack(side="right", fill="y")

# Button to load and display stored passwords
load_button = tk.Button(accounts_page, text="Load Passwords", command=load_passwords, **button_style)
load_button.pack(pady=10)

# Run the application
window.mainloop()
