from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from symmetric_encryption_scheme import SymmetricEncryptionScheme
import base64
import string
import random
import os


class AESEncryptionScheme(SymmetricEncryptionScheme):
  def __init__(self, symmetric_key: str):
     self.symmetric_key = base64.urlsafe_b64decode(symmetric_key) if symmetric_key else None

  def encode(self, plaintext):
      # Generate a random Initialization Vector (IV)
      iv = os.urandom(16)
      
      # Create a Cipher object with AES algorithm in CBC mode
      cipher = Cipher(algorithms.AES(self.symmetric_key), modes.CBC(iv), backend=default_backend())
      encryptor = cipher.encryptor()
      
      # Pad the plaintext to make it a multiple of the block size (16 bytes for AES)
      padder = PKCS7(128).padder()
      padded_data = padder.update(plaintext.encode()) + padder.finalize()
      
      # Encrypt the padded plaintext
      ciphertext = encryptor.update(padded_data) + encryptor.finalize()
      
      return iv + ciphertext
  
  def decode(self, ciphertext_with_iv):
      iv, ciphertext = ciphertext_with_iv[:16], ciphertext_with_iv[16:]

      # Create a Cipher object with AES algorithm in CBC mode
      cipher = Cipher(algorithms.AES(self.symmetric_key), modes.CBC(iv), backend=default_backend())
      decryptor = cipher.decryptor()

      # Decrypt the ciphertext
      padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

      # Remove padding
      unpadder = PKCS7(128).unpadder()
      plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

      return plaintext.decode()
  
  def _generate_adjusted_key(self, password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

  def _generate_random_string(self):
      # Combine letters and digits
      characters = string.ascii_letters + string.digits
      length = random.randint(5, 100)
      random_string = ''.join(random.choices(characters, k=length))
      return random_string
  
  def generate_key(self) -> str:
    random_password = self._generate_random_string()
    new_key = self._generate_adjusted_key(random_password, bytes([72, 101, 108, 108, 111]))
    return new_key
