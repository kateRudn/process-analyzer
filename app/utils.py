import threading

import pefile
import psutil
import hashlib
import os
import shutil

from peutils import SignatureDatabase
from signify.authenticode import SignedPEFile, AuthenticodeVerificationResult
from werkzeug.utils import secure_filename
import secrets

from psutil import process_iter
from os import startfile


def get_process_table():
    process_table = []
    for process in process_iter():
        # mem_info = process.memory_full_info()
        # res = process.as_dict()

        item = {}

        item['pid'] = process.pid
        item['name'] = process.name()
        item['status'] = process.status()

        process_table += [item]

    return process_table


def get_process_info(pid):
    # Iterate over the all the running process
    res_process_info = {}
    status = ''
    peid_result = ''
    sections_WX = ''
    for proc in psutil.process_iter():
        try:
            # process_info = proc.as_dict(attrs=['pid', 'name', 'create_time'])
            # Check if process name contains the given name string.
            if proc.pid == pid:
                process_info = proc.as_dict()
                cmd = proc.cmdline()
                res_process_info['cmd'] = " ".join(process_info['cmdline'])
                # ['environment_variables'] = "\n".join(process_info['environ'])
                # process_info['name'] = tmp_process_info['name']
                # process_info['pid'] = tmp_process_info['pid']
                # process_info['status'] = tmp_process_info['status']

                with open(process_info['exe'], "rb") as f:
                    # проверка цифровой подписи всех исполняемых файлов, используемых процессами;
                    pefile_check = SignedPEFile(f)
                    status, err = pefile_check.explain_verify()
                    if status != AuthenticodeVerificationResult.OK:
                        print(f"Invalid: {err}")

                # проверка исполняемых файлов на наличие признаков упаковки (например, с использованием утилиты Peid);
                signatures = SignatureDatabase('../files/PEID.txt')

                pe = pefile.PE(process_info['exe'])
                matches = signatures.match(pe, ep_only=True)

                if matches:
                    peid_result = 'matches'
                else:
                    peid_result = 'not matches'

                sections_WX = []
                for section in pe.sections:
                    if section.IMAGE_SCN_MEM_EXECUTE and section.IMAGE_SCN_MEM_WRITE:
                        sections_WX += [section.Name]

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            res_process_info = "Error"
            pass
        except Exception as ex:
            # process_info = "Error"
            pass
        # print(status, peid_result, sections_WX)
    return status, peid_result, sections_WX


if __name__ == '__main__':
    print(get_process_table())
    print(get_process_info(0))
