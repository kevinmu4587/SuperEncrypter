import sys
from aes_encryption_use_case import AESEncryptionScheme
from symmetric_encryption_scheme import SymmetricEncryptionScheme


def decrypt_loop(encryption_scheme: SymmetricEncryptionScheme):
    key = encryption_scheme.get_key()

    while (True):
        ciphertext = input("Enter the message to decode (Q to return to main menu): ")
        if ciphertext == "Q":
            return
        plaintext = encryption_scheme.decrypt(ciphertext.encode("utf-8"))
        print(plaintext)

def generate_new_key_loop(encryption_scheme: SymmetricEncryptionScheme):
    while(True):
        new_key = encryption_scheme.generate_key()
        
        print("Here is your key, keep it somewhere safe.")
        print(new_key.decode('utf-8'))
        option = input("Enter R to regenerate, Q to return to main menu: ")
        if option == "Q":
            return
        

def encrypt_loop(encryption_scheme: SymmetricEncryptionScheme):
    while(True):
        plaintext = input("Please enter the plaintext to encode (Q to return to main menu): ")
        if plaintext == "Q":
            return
        ciphertext = encryption_scheme.encrypt(plaintext.encode("utf-8"))
        print(ciphertext)


def print_options():
    print("Enter D to decode (key required).")
    print("Enter E to encode (key required).")
    print("Enter K to generate a new key.")
    print("Enter Q to exit.")


def main():
    print("Welcome to Super Encrypter.")
    print("What would you like to do?")

    encryption_scheme = AESEncryptionScheme(symmetric_key=None)
    while (True):
        option = input("Enter an option (Press L for options): ")
        if not encryption_scheme.symmetric_key and option in ["D", "E"]:
            key = input("Please enter your key: ")
            encryption_scheme = AESEncryptionScheme(key)
        
        if option == "D":
            decrypt_loop(encryption_scheme)
        elif option == "E":
            encrypt_loop(encryption_scheme)
        elif option == "K":
            generate_new_key_loop(encryption_scheme)
        elif option == "L":
            print_options()
        elif option == "Q":
            sys.exit()
        else:
            print("Invalid option, try again.")


if __name__ == "__main__":
    main()
