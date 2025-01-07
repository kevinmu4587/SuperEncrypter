from abc import ABC, abstractmethod

class SymmetricEncryptionScheme(ABC):
    def __init__(self, symmetric_key):
        self.symmetric_key = symmetric_key

    def get_key(self) -> str:
        return self.symmetric_key

    @abstractmethod
    def encode(self):
        pass

    @abstractmethod
    def decode(self):
        pass

    @abstractmethod
    def generate_key(self):
        pass