import json
import os
import logging

logger = logging.getLogger()
logger.setLevel('INFO')

SETTINGS = {
    'initial_file': 'data/initial_file.txt',
    'encrypted_file': 'data/encrypted_file.txt',
    'decrypted_file': 'data/decrypted_file.txt',
    'symmetric_key': 'data/symmetric_key.txt',
    'public_key': 'data/public_key.pem',
    'secret_key': 'data/secret_key.pem',
}

if __name__ == '__main__':
    try:
        with open(os.path.join('data', 'settings.json'), 'w') as fp:
            json.dump(SETTINGS, fp)
        logging.info("Настройки записаны")
    except OSError as err:
        logging.warning(f'{err} ошибка при записи в файл')