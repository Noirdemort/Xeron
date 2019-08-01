from PyQt5.QtWidgets import QWidget, QHBoxLayout, QVBoxLayout, QPushButton, QLabel, QLineEdit, QTextEdit, qApp, QFileDialog, QPlainTextEdit, QTextBrowser, QMessageBox
from PyQt5.QtCore import Qt
# from PyQt5.QtWidgets import *
from pathlib import Path
import os
# from PyQt5.QtGui import *
from coreutils import encrypt, decrypt, getKeyFromUrl


class Xenon(QWidget):

    def __init__(self):
        super().__init__()
        home = str(Path.home())
        with open(home+'/winds/private.pem', 'r') as file:
            self.privateKey = file.read()
        self.initiate()

    def initiate(self):
        self.setWindowTitle("Xenon Desktop")
        self.setGeometry(700, 500, 500, 500)

        h1 = QHBoxLayout()
        h2 = QHBoxLayout()
        h3 = QHBoxLayout()
        h4 = QHBoxLayout()

        # for h1
        title = QLabel("Xenon - RSA Encryption")

        title.setAlignment(Qt.AlignHCenter)
        h1.addWidget(title)

        # for h2
        # uploadLabel = QLabel("Key upload:")
        # uploadPrivateKey = QPushButton("Add Private Key Locally")
        # uploadPrivateKey.clicked.connect(self.openFile)
        generateButton = QPushButton("Generate RSA Key pair")
        generateButton.clicked.connect(self.generateRSAPair)
        self.privateKeyLabel = QLabel()

        # h2.addWidget(uploadLabel)
        h2.addWidget(generateButton)
        h2.addWidget(self.privateKeyLabel)
        # h2.addWidget(uploadPrivateKey)

        # for h3
        tv1 = QVBoxLayout()
        encryptionLabel = QLabel('Encrypt')
        encryptionLabel.setAlignment(Qt.AlignHCenter)
        self.remoteURLInput = QLineEdit()
        self.remoteURLInput.setPlaceholderText('Remote URL of public key')
        orLabel = QLabel('Or')
        orLabel.setAlignment(Qt.AlignCenter)
        self.publicKeyInput = QLineEdit()
        self.publicKeyInput.setPlaceholderText('Paste Public Key here')
        self.clearTextEdit = QPlainTextEdit()
        self.clearTextEdit.setPlaceholderText('Paste or Type cleartext here')
        encryptButton = QPushButton('Encrypt Message')
        encryptButton.clicked.connect(self.encryptMessage)
        self.encryptedTextBrowser = QTextBrowser()
        self.encryptedTextBrowser.setPlaceholderText(
            'Encrypted Text Appears Here')

        tv1.addWidget(encryptionLabel)
        tv1.addWidget(self.remoteURLInput)
        tv1.addWidget(orLabel)
        tv1.addWidget(self.publicKeyInput)
        tv1.addWidget(self.clearTextEdit)
        tv1.addWidget(encryptButton)
        tv1.addWidget(self.encryptedTextBrowser)

        tv2 = QVBoxLayout()
        decryptionLabel = QLabel('Decrypt')
        decryptionLabel.setAlignment(Qt.AlignHCenter)
        self.cipherTextEdit = QPlainTextEdit()
        self.cipherTextEdit.setPlaceholderText('Paste encrypted text here')
        decryptButton = QPushButton('Decrypt Message')
        decryptButton.clicked.connect(self.decryptMessage)
        self.decryptedTextBrowser = QTextBrowser()
        self.decryptedTextBrowser.setPlaceholderText(
            'Decrypted Text Appears Here')

        tv2.addWidget(decryptionLabel)
        tv2.addWidget(self.cipherTextEdit)
        tv2.addWidget(decryptButton)
        tv2.addWidget(self.decryptedTextBrowser)

        h3.addLayout(tv1)
        h3.addLayout(tv2)

        # for h4
        exit = QPushButton("Exit")
        exit.clicked.connect(qApp.quit)
        h4.addWidget(exit)

        # final view
        v = QVBoxLayout()
        v.addLayout(h1)
        v.addLayout(h2)
        v.addLayout(h3)
        v.addLayout(h4)
        self.setLayout(v)

    def openFile(self):
        self.fileName = QFileDialog.getOpenFileName(self, 'OpenFile')
        print(self.fileName)
        with open(self.fileName[0], 'r') as file:
            self.privateKey = file.read()
        self.privateKeyLabel.setText(self.fileName[0])

    def encryptMessage(self):
        if self.publicKeyInput.text() and self.clearTextEdit.toPlainText():
            cipher = encrypt(self.publicKeyInput.text(),
                             self.clearTextEdit.toPlainText())
            self.encryptedTextBrowser.setText(cipher)
        elif self.remoteURLInput.text() and self.clearTextEdit.toPlainText():
            print(self.remoteURLInput.text())
            remote_public_key = getKeyFromUrl(self.remoteURLInput.text())
            cipher = encrypt(remote_public_key,
                             self.clearTextEdit.toPlainText())
            self.encryptedTextBrowser.setText(cipher)
        else:
            w = QMessageBox()
            w.setText(
                "Public key or remote url and cleartext is required.")
            w.exec_()

    def decryptMessage(self):
        if self.privateKey and self.cipherTextEdit.toPlainText():
            clearText = decrypt(
                self.privateKey, self.cipherTextEdit.toPlainText())
            self.decryptedTextBrowser.setText(clearText)
        else:
            w = QMessageBox()
            w.setText(
                "Private key and encrypted text are required.")
            w.exec_()

    def generateRSAPair(self):
        os.system("mkdir -p $HOME/winds")
        os.system('openssl genrsa -out $HOME/winds/private.pem 2048')
        os.system(
            'openssl rsa -in $HOME/winds/private.pem -outform PEM -pubout -out $HOME/winds/public.pem')
        home = str(Path.home())
        with open(home+'/winds/private.pem', 'r') as file:
            self.privateKey = file.read()
        self.privateKeyLabel.setText(
            'Keys Generated successfully! Upload public key to server for others to find')
