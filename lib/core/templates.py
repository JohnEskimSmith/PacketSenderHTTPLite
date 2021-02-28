from base64 import b64encode
from hashlib import sha256, sha1, md5
from aiohttp import ClientResponse
from hexdump import hexdump
from typing import Dict

from .configs import Target, AppConfig

# __all__ = ['create_result_template', 'create_template_struct', 'create_error_template', 'make_document_from_response']
__all__ = ['create_template_struct', 'create_error_template']


# def create_result_template(target: Target) -> dict:
#     """
#     Creates result dictionary skeleton
#     """
#     result = {'data': {'tcp': {'status': 'tcp', 'result': {'response': {'request': {}}}}}}
#     if target.ssl_check:
#         tls_log = {'handshake_log': {'server_certificates': {'certificate': {'parsed': {}, 'raw': ''}}}}
#         result['data']['tcp']['result']['response']['request']['tls_log'] = tls_log
#     return result


def create_template_struct(target: Target) -> dict:
    """
    такая структура у результатов в модуле zgrab2 http - поэтому ее так и повторил
    :return:
    """

    result = {'data':
              {'http':
               {'status': 'http',
                'result':
                {'response':
                 {'request': {}
                  }},

                }
               }
              }
    _tls_log = {'tls_log':
                {'handshake_log':
                 {'server_certificates':
                  {'certificate': {'parsed': {},
                                   'raw': ''}}
                  }
                 }
                }
    if target.ssl_check:
        result['data']['http']['result']['response']['request'].update(
            _tls_log)
    result['data']['http']['result']['response']['request']['url'] = {}
    result['data']['http']['result']['response']['request']['url']['scheme'] = target.scheme
    if len(target.hostname) > 0:
        result['data']['http']['result']['response']['request']['url']['host'] = target.hostname
        result['host'] = target.hostname
        result['data']['http']['result']['response']['request']['host'] = target.hostname
    elif len(target.ip) > 0:
        result['data']['http']['result']['response']['request']['url']['host'] = target.ip
        result['data']['http']['result']['response']['request']['host'] = target.ip
    result['data']['http']['result']['response']['request']['url']['path'] = target.endpoint
    result['data']['http']['result']['response']['request']['method'] = target.method
    return result


def create_error_template(target: Target, error_str: str) -> dict:
    _tmp = {}
    if target.ip:
        _tmp['ip'] = target.ip
    if target.hostname:
        _tmp['hostname'] = target.hostname
    if target.port:
        _tmp['port'] = target.port
    _tmp['data'] = {}
    _tmp["data"]["http"] = {}
    _tmp["data"]["http"]["status"] = "unknown-error"
    _tmp["data"]["http"]["error"] = error_str
    return _tmp

# def create_error_template(target: Target, error_str: str) -> dict:
#     """
#     Creates skeleton of error result dictionary
#     """
#     return {
#         'ip': target.ip,
#         'port': target.port,
#         'data': {
#             'http': {
#                 'status': 'unknown-error',
#                 'error': error_str
#             }
#         }
#     }

# async def make_document_from_response(response: ClientResponse, target, app_settings: AppConfig) -> Dict:
#
#     def update_line(json_record, target):
#         json_record['ip'] = target.ip
#         # json_record['ip_v4_int'] = int(ip_address(target.ip))
#         # json_record['datetime'] = datetime.datetime.utcnow()
#         # json_record['port'] = int(target.port)
#         return json_record
#
#     if not (app_settings['status_code'] == CONST_ANY_STATUS):
#         if app_settings['status_code'] != response.status:
#             return None
#
#     _default_record = create_template_struct(target)
#     if target.sslcheck:
#         cert = convert_bytes_to_cert(response.peer_cert)
#         if not app_settings['without_certraw']:
#             _default_record['data']['http']['result']['response']['request']['tls_log']['handshake_log'][
#                 'server_certificates']['certificate']['raw'] = base64.b64encode(response.peer_cert).decode('utf-8')
#         if cert:
#             _default_record['data']['http']['result']['response']['request']['tls_log'][
#                 'handshake_log']['server_certificates']['certificate']['parsed'] = cert
#
#     _default_record['data']['http']['status'] = "success"
#     _default_record['data']['http']['result']['response']['status_code'] = response.status
#     _header = {}
#
#     for key in response.headers:
#         _header[key.lower().replace('-', '_')] = response.headers.getall(key)
#     _default_record['data']['http']['result']['response']['headers'] = _header
#     if target.method in ['GET', 'POST', 'PUT', 'DELETE', 'UPDATE']:
#
#         buffer = b""
#         try:
#             buffer = await readcontent(response, n=target.max_size)
#         except Exception as e:
#             pass
#
#         _default_record['data']['http']['result']['response']['content_length'] = len(
#             buffer)
#         _default_record['data']['http']['result']['response']['body'] = ''
#         try:
#             _default_record['data']['http']['result']['response']['body'] = buffer.decode(
#             )
#         except Exception as e:
#             pass
#         #
#         if not app_settings['without_base64']:
#             try:
#                 _base64_data = base64.b64encode(buffer).decode('utf-8')
#                 _default_record['data']['http']['result']['response']['body_raw'] = _base64_data
#             except Exception as e:
#                 pass
#         try:
#             hashs = {'sha256': sha256,
#                      'sha1': sha1,
#                      'md5': md5}
#             for namehash, func in hashs.items():
#                 hm = func()
#                 hm.update(buffer)
#                 _default_record['data']['http']['result']['response'][f'body_{namehash}'] = hm.hexdigest(
#                 )
#         except Exception as e:
#             pass
#         if not app_settings['without_hexdump']:
#             _default_record['data']['http']['result']['response']['body_hexdump'] = ''
#             try:
#                 hdump = hexdump(buffer, result='return')
#                 _output = base64.b64encode(bytes(hdump, 'utf-8'))
#                 output = _output.decode('utf-8')
#                 _default_record['data']['http']['result']['response']['body_hexdump'] = output
#             except Exception as e:
#                 pass
#     result_to_output = update_line(_default_record, target)
#     return result_to_output
#
# # noinspection PyBroadException
# def make_document_from_response(buffer: bytes, target: Target) -> dict:
#     """
#     Обработка результата чтения байт из соединения
#     - buffer - байты полученные от сервиса(из соединения)
#     - target - информация о цели (какой порт, ip, payload и так далее)
#     результат - словарь с результатом, который будет отправлен в stdout
#     """
#
#     result = create_result_template(target)
#     result['data']['tcp']['status'] = 'success'
#     result['data']['tcp']['result']['response']['content_length'] = len(buffer)
#     try:
#         result['data']['tcp']['options'] = target.additions
#     except BaseException:
#         pass
#     # region ADD DESC.
#     # отказался от попыток декодировать данные
#     # поля data.tcp.result.response.body - не будет, так лучше
#     # (в противном случае могут возникать проблемы при создании json
#     # из данных с декодированным body)
#     # try:
#     #     _default_record['data']['tcp']['result']['response']['body'] = buffer.decode()
#     # except Exception as e:
#     #     pass
#     # endregion
#     try:
#         result['data']['tcp']['result']['response']['body_raw'] = b64encode(buffer).decode('utf-8')
#         # _base64_data - содержит байты в base64 - для того чтоб их удобно было
#         # отправлять в stdout
#     except Exception:
#         pass
#     try:
#         # функции импортированные из hashlib для подсчета хэшей
#         # sha256, sha1, md5
#         hashes = {'sha256': sha256, 'sha1': sha1, 'md5': md5}
#         for algo, func in hashes.items():
#             hm = func()
#             hm.update(buffer)
#             result['data']['tcp']['result']['response'][f'body_{algo}'] = hm.hexdigest()
#     except Exception:
#         pass
#     result['data']['tcp']['result']['response']['body_hexdump'] = ''
#     try:
#         # еще одно представление результата(байт)
#         # Transform binary data to the hex dump text format:
#         # 00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  .........
#         # для этого и необходим модуль hexdump
#         hdump = hexdump(buffer, result='return')
#         output = b64encode(bytes(hdump, 'utf-8')).decode('utf-8')
#         result['data']['tcp']['result']['response']['body_hexdump'] = output
#     except Exception:
#         pass
#     result['ip'] = target.ip
#     result['port'] = int(target.port)
#     return result
