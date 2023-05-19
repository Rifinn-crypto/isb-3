import logging

from cryptography.hazmat.primitives.asymmetric import padding
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