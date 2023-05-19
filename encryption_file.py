import logging
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as s_padding
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger()
logger.setLevel('INFO')


def encryption_assymetric(public_key, symmetric_key: bytes) -> bytes:
    """
        Ассиметричное шифрование симметричного ключа.
        :param public_key: Открытый ключ.
        :param symmetric_key: Текст.
    """
    c_text = public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                  algorithm=hashes.SHA256(), label=None))
    return c_text


def encryption_symmetric(r_file: str, symmetric_key: bytes, w_file: str) -> None:
    """
        Шифрование текста симметричным алгоритмом и сохранение по указанному пути.
        :param r_file: Путь к файлу с зашифрованным текстом.
        :param symmetric_key: Симметричный ключ.
        :param w_file: Путь к файлу сохранения.
    """
    try:
        with open(r_file, 'r', encoding='utf-8') as text_file:
            text = text_file.read()
        logging.info('Текст считан из r_file')
    except OSError as err:
        logging.warning(f'{err} Ошибка при чтении r_file')
    padder = s_padding.ANSIX923(64).padder()
    padded_text = padder.update(bytes(text, 'utf-8')) + padder.finalize()
    iv = os.urandom(8)
    cipher = Cipher(algorithms.IDEA(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_text) + encryptor.finalize()
    cipher_text = iv + cipher_text
    logging.info('Текст зашифрован!')
    try:
        with open(w_file, 'wb') as f_text:
            f_text.write(cipher_text)
        logging.info('Текст записан в w_file')
    except OSError as err:
        logging.warning(f'{err} Ошибка при записи текста в w_file')


