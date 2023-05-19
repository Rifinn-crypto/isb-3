import logging
import argparse
import json
import os


def read_settings(file: str) -> dict:
    """ Считывает настройки из файла.
        :param file: Путь к файлу.
    """
    try:
        with open(file) as json_f:
            data = json.load(json_f)
        logging.info('Настройки считаны')
    except OSError as err:
        logging.warning(f'{err} Ошибка при чтении файла')
    return data

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-set', '--settings', type=str, help='Использовать собственный файл с настройками (Введите '
                                                             'путь к файлу)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', help='Запускает режим генерации ключей')
    group.add_argument('-enc', '--encryption', help='Запускает режим шифрования')
    group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования')
    args = parser.parse_args()
    if args.settings:
        settings = read_settings(args.settings)
    else:
        settings = read_settings(os.path.join("data", "settings.json"))