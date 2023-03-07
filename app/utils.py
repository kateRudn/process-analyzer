import pefile
from signify.authenticode import SignedPEFile, AuthenticodeVerificationResult
from psutil import process_iter
import pymem
from app import signatures

process_table = {}
dll_verify = {}


def get_process_table():

    global process_table

    for process in process_iter():

        try:
            if process.pid not in process_table.keys() or process.name() != process_table[process.pid]['name']:
                item, item_dll = get_process_info(process)
                process_table[process.pid] = item
                if item_dll:
                    process_table[process.pid]['dll'] = item_dll
        except:
            pass

    sort_process_table = dict(sorted(process_table.items(), key=lambda k: k[1]['weight'], reverse=True))

    return sort_process_table


def verify_signature(file):
    with open(file, "rb") as f:
        pefile_check = SignedPEFile(f)
        status, err = pefile_check.explain_verify()
        if status != AuthenticodeVerificationResult.OK:
            return 'no'
        else:
            return 'yes'


def is_packed(file):
    try:
        pe = pefile.PE(file)
        matches = signatures.match(pe, ep_only=True)
        if matches:
            return 'yes'
        else:
            return 'no'
    except Exception as ex:
        return 'no'


def is_section_wx(file):
    sections_wx = []
    try:
        pe = pefile.PE(file)
        for section in pe.sections:
            if section.IMAGE_SCN_MEM_EXECUTE and section.IMAGE_SCN_MEM_WRITE:
                sections_wx += [section.Name.decode("utf-8")]
        return sections_wx
    except Exception as ex:
        return sections_wx


def process_verify_memory(pid, pe):
    memory_result = {'result': 'Ok', 'diff': [], 'wght': 0}
    try:
        process = pymem.Pymem(pid)
        process_module = list(process.list_modules())[0]

        for section in pe.sections:
            if section.IMAGE_SCN_MEM_EXECUTE:
                section_address = process_module.lpBaseOfDll + section.VirtualAddress
                # код из процесса
                process_mem_dump = process.read_bytes(section_address, section.SizeOfRawData)
                # код из exe
                section_from_exe = section.get_data()

                for i in range(0, section.SizeOfRawData):
                    if process_mem_dump[i] != section_from_exe[i]:
                        memory_result['diff'] += [{
                            'section_name': section.Name.decode("utf-8"),
                            'section_address': section_address,
                            'offset': i,
                            'address': hex(section_address + i),
                            'byte_exe': hex(section_from_exe[i]),
                            'byte_memory': hex(process_mem_dump[i])
                        }]
        memory_result['wght'] = len(memory_result['diff']) / section.SizeOfRawData
        return memory_result
    except Exception as ex:
        memory_result['result'] = "Error"
        return memory_result


def get_process_info(process):
    global dll_verify

    process_info = process.as_dict()

    item = {}
    item_dll = {}

    item['pid'] = process.pid
    item['name'] = process.name()
    item['weight'] = 0
    item['memory'] = 'ok'

    try:
        item['pathexe'] = process_info['exe']
    except:
        item['pathexe'] = '...'

    try:
        verify = verify_signature(process_info['exe'])
        item['signexe'] = verify
        if verify == 'no':
            item['weight'] += 0.2
    except:
        item['signexe'] = '...'

    try:
        peid_result = is_packed(process_info['exe'])
        item['packexe'] = peid_result
        if peid_result == 'yes':
            item['weight'] += 0.2
    except:
        item['packexe'] = '...'

    try:
        sections_WX = is_section_wx(process_info['exe'])
        item['wxexe'] = sections_WX
        if len(sections_WX) != 0:
            item['weight'] += 0.5 * len(sections_WX)
    except:
        item['wxexe'] = '...'

    try:
        verify_memory = process_verify_memory(process.pid, pefile.PE(process_info['exe']))
        if verify_memory['wght'] != 0:
            item['weight'] += verify_memory['wght']
            item['memory'] = 'ne ok'
    except:
        item['memory'] = '...'

    try:
        for dll in process.memory_maps():
            if dll.path not in dll_verify:
                item_dll[dll.path] = verify_signature(dll.path)
                dll_verify[dll.path] = item_dll[dll.path]
            else:
                item_dll[dll.path] = dll_verify[dll.path]
            if item_dll[dll.path] == 'no':
                item['weight'] += 0.05

    except Exception as ex:
        return item, item_dll

    return item, item_dll


if __name__ == '__main__':
    print(get_process_table())

