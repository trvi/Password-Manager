import os
import json
import sys
from PyQt5 import QtWidgets, QtGui, QtCore
from cryptography.fernet import Fernet

# Generate a key for encryption
def generate_key():
    return Fernet.generate_key()

# Load or create a new key
def load_key():
    if os.path.exists("key.key"):
        with open("key.key", "rb") as key_file:
            return key_file.read()
    else:
        key = generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
        return key

# Encrypt the password
def encrypt_password(password, key):
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())
    return encrypted_password

# Decrypt the password
def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    decrypted_password = f.decrypt(encrypted_password).decode()
    return decrypted_password

# Load passwords from file
def load_passwords():
    if os.path.exists("passwords.json"):
        with open("passwords.json", "r") as f:
            return json.load(f)
    return {}

# Save passwords to file
def save_passwords(passwords):
    with open("passwords.json", "w") as f:
        json.dump(passwords, f)

class PasswordManager(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.key = load_key()
        self.passwords = load_passwords()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 400, 300)

        # Create layout
        layout = QtWidgets.QVBoxLayout()

        # Create buttons
        self.add_button = QtWidgets.QPushButton("Add Password")
        self.add_button.clicked.connect(self.add_password)
        layout.addWidget(self.add_button)

        self.view_button = QtWidgets.QPushButton("View Passwords")
        self.view_button.clicked.connect(self.view_passwords)
        layout.addWidget(self.view_button)

        self.delete_button = QtWidgets.QPushButton("Delete Password")
        self.delete_button.clicked.connect(self.delete_password)
        layout.addWidget(self.delete_button)

        self.exit_button = QtWidgets.QPushButton("Exit")
        self.exit_button.clicked.connect(self.close)
        layout.addWidget(self.exit_button)

        # Create text area
        self.text_area = QtWidgets.QTextEdit()
        self.text_area.setReadOnly(True)
        layout.addWidget(self.text_area)

        self.setLayout(layout)

    def add_password(self):
        site, ok1 = QtWidgets.QInputDialog.getText(self, "Site Name", "Enter the site name:")
        if ok1 and site:
            password, ok2 = QtWidgets.QInputDialog.getText(self, "Password", "Enter the password:", QtWidgets.QLineEdit.Password)
            if ok2 and password:
                encrypted_password = encrypt_password(password, self.key)
                self.passwords[site] = encrypted_password.decode()
                save_passwords(self.passwords)
                QtWidgets.QMessageBox.information(self, "Success", "Password saved!")

    def view_passwords(self):
        if self.passwords:
            stored_passwords = ""
            for site, encrypted_password in self.passwords.items():
                decrypted_password = decrypt_password(encrypted_password.encode(), self.key)
                stored_passwords += f"{site}: {decrypted_password}\n"
            self.text_area.setPlainText(stored_passwords)
        else:
            QtWidgets.QMessageBox.information(self, "Stored Passwords", "No passwords stored.")

    def delete_password(self):
        site, ok = QtWidgets.QInputDialog.getText(self, "Delete Password", "Enter the site name to delete:")
        if ok and site in self.passwords:
            del self.passwords[site]
            save_passwords(self.passwords)
            QtWidgets.QMessageBox.information(self, "Success", "Password deleted!")
        elif ok:
            QtWidgets.QMessageBox.warning(self, "Error", "Site not found.")

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec_())