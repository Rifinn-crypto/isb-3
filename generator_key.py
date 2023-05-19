import os
import logging

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_symmetric_k() -> bytes:
    """ Генерация симметричного ключа """
    key = os.urandom(16)
    return key

def write_symmetric_k(file: str, symmetric_key: bytes) -> None:
    """
       Запись симметричного ключа в файл.
       :param file: Путь к файлу.
       :param symmetric_key: Симметричный ключ.
    """
    try:
        with open(file, "wb") as key_w:
            key_w.write(symmetric_key)
        logging.info('Симметричный ключ записан')
    except OSError as err:
        logging.warning(f'{err} Ошибка при записи симметричного ключа')


def generate_asymmetric_k(private_k: str, public_k: str) ->bytes:
    """
        Генерация суперсекретного и не очень ключей и их запись в файл
        :param private_k: Путь к приватному ключу.
        :param public_k: Путь к открытому ключу.
    """
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()

    try:
        with open(public_k, 'wb') as public_write:
            public_write.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))
        logging.info('Открытый ключ записан')
    except OSError as err:
        logging.warning(f'{err} Ошибка при записи открытого ключа')
    try:
        with open(private_k, 'wb') as private_write:
            private_write.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                        encryption_algorithm=serialization.NoEncryption()))
        logging.info('Приватный ключ записан')
    except OSError as err:
        logging.warning(f'{err} Ошибка при записи приватного ключа ')
    return public_key