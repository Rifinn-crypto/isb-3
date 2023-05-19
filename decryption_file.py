import logging

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as s_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger()
logger.setLevel('INFO')


def decryption_assymetric(private_k_pem: str, symmetric_k_file: str) -> bytes:
    """
       Дешифрование симметричного ключа асимметричным алгоритмом
       :param private_k_pem: Путь к приватному ключу.
       :param symmetric_k_file: Путь к симметричному ключу.
    """
    try:
        with open(private_k_pem, 'rb') as pem_in:
            private_bytes = pem_in.read()
        private_key = load_pem_private_key(private_bytes, password=None)
        logging.info('Приватный ключ считан')
    except OSError as err:
        logging.warning(f'{err} Ошибка при чтении приватного ключа')
    try:
        with open(symmetric_k_file, mode='rb') as key_file:
            key = key_file.read()
        logging.info('Симметричный ключ считан')
    except OSError as err:
        logging.warning(f'{err} Ошибка при чтении симметричного ключа')

    return private_key.decrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                 algorithm=hashes.SHA256(), label=None))


def decryption_symmetric(read_file: str, symmetric_key: bytes, write_file: str) -> None:
    """
       Дешифрование текста симметричным алгоритмом и сохранение по указанному пути.
       :param read_file: Путь к файлу с зашифрованным текстом.
       :param symmetric_key: Симметричный ключ.
       :param write_file: Путь к файлу сохранения.
    """
    try:
        with open(read_file, 'rb') as text_file:
            c_text = text_file.read()
        logging.info('Текст считан')
    except OSError as err:
        logging.warning(f'{err} Ошибка при чтении')
    c_text, iv = c_text[8:], c_text[:8]
    cipher = Cipher(algorithms.IDEA(symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dc_text = decryptor.update(c_text) + decryptor.finalize()
    unpadder = s_padding.ANSIX923(64).unpadder()
    unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
    logging.info('Текст расшифрован!')
    try:
        with open(write_file, 'wb') as f:
            f.write(unpadded_dc_text)
        logging.info('Текст записан')
    except OSError as err:
        logging.warning(f'{err} Ошибка при записи текста')