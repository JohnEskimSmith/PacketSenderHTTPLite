from base64 import b64encode
from ipaddress import ip_network
from typing import Iterator, Generator, Optional, Dict
from urllib.parse import urlparse
from re import compile as re_compile
from lib.core import Target, load_python_generator_payloads_from_file, TargetConfig, PayloadGenerator
from lib.util import is_ip, is_network, encode_files_payload
from ujson import loads as ujson_loads
from pickle import loads as pickle_loads
RESERVED_CHAR = ';'  # for spliting endpoints, I don't want use narg


def create_target_http_protocol(raw_str: str,
                                target_config: TargetConfig,
                                target_type: str) -> Iterator[Target]:
    """
    На основании ip адреса и настроек возвращает через yield экзэмпляр Target.
    Каждый экземпляр Target содержит всю необходимую информацию(настройки и параметры) для функции worker.
    """
    if target_type == 'network':
        target_ip = raw_str
        endpoints = target_config.endpoint.split(RESERVED_CHAR)
        for endpoint in endpoints:
            kwargs = target_config.as_dict()
            url = f'{target_config.scheme}://{target_ip}:{target_config.port}{endpoint}'
            if target_config.list_payloads:
                for payload in target_config.list_payloads:
                    _headers: Dict = target_config.headers
                    data_payload = payload
                    if (target_config.single_payload_type).lower() == 'data':
                        data_payload = payload
                    elif (target_config.single_payload_type).lower() == 'json':
                        pass
                    elif (target_config.single_payload_type).lower() == 'files': # TODO add exception
                        # _target_payload_string = (payload).decode('utf-8')
                        # target_payload_dict = ujson_loads(_target_payload_string)
                        # пока иначе не придумал
                        # TODO: переосмыслить
                        try:
                            target_payload_dict = pickle_loads(payload)
                            assert isinstance(target_payload_dict, dict)
                        except:
                            pass
                        else:
                            data_payload, _headers = encode_files_payload(files=target_payload_dict,
                                                                          data=None,
                                                                          headers=target_config.headers)
                    additions = {'data_payload': {'payload_raw': b64encode(payload).decode('utf-8'), 'variables': []}}
                    try:
                        kwargs.pop('headers')
                        kwargs.pop('endpoint')
                    except:
                        pass
                    target_instance = Target(ip=target_ip,
                                             url=url,
                                             headers=_headers,
                                             payload=data_payload,
                                             endpoint=endpoint,
                                             additions=additions, **kwargs)
                    yield target_instance
            elif target_config.python_payloads:
                payloads_generator = get_generator(target_config)
                for payload in payloads_generator(target_ip, target_type, kwargs):
                    payload = payload['payload']
                    additions = payload['data_payload']
                    _headers: Dict = target_config.headers
                    data_payload = payload
                    if (target_config.single_payload_type).lower() == 'data':
                        data_payload = payload
                    elif (target_config.single_payload_type).lower() == 'json':
                        pass
                    elif (target_config.single_payload_type).lower() == 'files': # TODO add exception
                        # пока иначе не придумал
                        # TODO: переосмыслить
                        try:
                            target_payload_dict = pickle_loads(payload)
                            assert isinstance(target_payload_dict, dict)
                        except:
                            pass
                        else:
                            data_payload, _headers = encode_files_payload(files=target_payload_dict,
                                                                          data=None,
                                                                          headers=target_config.headers)
                    try:
                        kwargs.pop('headers')
                        kwargs.pop('endpoint')
                    except:
                        pass
                    target_instance = Target(ip=target_ip,
                                             url=url,
                                             payload=data_payload,
                                             headers=_headers,
                                             endpoint=endpoint,
                                             additions=additions, **kwargs)
                    yield target_instance
            else:
                try:
                    kwargs.pop('endpoint')
                except:
                    pass
                target_instance = Target(ip=target_ip, url=url, payload=None, additions=None, endpoint=endpoint, **kwargs)
                yield target_instance
    elif target_type == 'hostname':
        endpoints = target_config.endpoint.split(RESERVED_CHAR)
        for endpoint in endpoints:
            kwargs = target_config.as_dict()
            hostname = raw_str
            if 'hostname' in kwargs.keys():
                kwargs.pop('hostname')

            url = f'{target_config.scheme}://{hostname}:{target_config.port}{endpoint}'
            if target_config.list_payloads:
                for payload in target_config.list_payloads:
                    additions = {'data_payload': {'payload_raw': b64encode(payload).decode('utf-8'), 'variables': []}}
                    try:
                        kwargs.pop('endpoint')
                    except:
                        pass
                    target_instance = Target(hostname=hostname,
                                             url=url,
                                             ip='',
                                             endpoint=endpoint,
                                             payload=payload,
                                             additions=additions,
                                             **kwargs)
                    yield target_instance
            elif target_config.python_payloads:
                payloads_generator = get_generator(target_config)
                for payload in payloads_generator(hostname, target_type, kwargs):
                    payload = payload['payload']
                    additions = payload['data_payload']
                    try:
                        kwargs.pop('endpoint')
                    except:
                        pass
                    target_instance = Target(hostname=hostname,
                                             url=url,
                                             ip='',
                                             payload=payload,
                                             additions=additions,
                                             endpoint=endpoint,
                                             **kwargs)
                    yield target_instance
            else:
                try:
                    kwargs.pop('endpoint')
                except:
                    pass
                target_instance = Target(hostname=hostname, ip='',
                                         url=url,
                                         payload=None,
                                         additions=None,
                                         endpoint=endpoint,
                                         **kwargs)
                yield target_instance
    elif target_type == 'url':
        kwargs = target_config.as_dict()
        url_line = urlparse(raw_str)
        url = raw_str
        hostname = url_line.hostname
        scheme: str = url_line.scheme
        if not hasattr(url_line, 'port'):
            if scheme == 'https':
                port = 443  # default port
            elif scheme == 'http':
                port = 80
        else:
            port = url_line.port
        ip = ''
        _keys = ['url', 'ip', 'port', 'hostname']
        for k in _keys:
            if k in kwargs.keys():
                kwargs.pop(k)
        _struct = {'hostname': hostname,
                   'ip': ip,
                   'port': port,
                   'url': url}
        if target_config.list_payloads:
            for payload in target_config.list_payloads:
                additions = {'data_payload': {'payload_raw': b64encode(payload).decode('utf-8'), 'variables': []}}
                target_instance = Target(payload=payload, additions=additions, **_struct, **kwargs)
                yield target_instance
        elif target_config.python_payloads:
            payloads_generator = get_generator(target_config)
            for payload in payloads_generator(hostname, target_type, kwargs):
                payload = payload['payload']
                additions = payload['data_payload']
                target_instance = Target(payload=payload, additions=additions, **_struct, **kwargs)
                yield target_instance
        else:
            target_instance = Target(payload=None, additions=None, **_struct, **kwargs)
            yield target_instance


def get_generator(target_config: TargetConfig) -> Optional[PayloadGenerator]:
    func_name = 'generator_payloads'
    if target_config.generator_payloads:
        func_name = target_config.generator_payloads.strip('"').strip("'")
    path_to_module = target_config.python_payloads.strip('"').strip("'")
    payloads_generator = load_python_generator_payloads_from_file(path_to_module, func_name)
    return payloads_generator


def create_targets_http_protocol(raw_str: str, target_settings: TargetConfig) -> Generator[Target, None, None]:
    """
    Функция для обработки и создания "целей"
    """
    def detect_url(input_str: str) -> bool:
        url_line = urlparse(input_str)
        host = url_line.netloc
        scheme = url_line.scheme
        return bool(host and scheme)

    def detect_domain(value) -> bool:
        """
            Validating Domain Names
        :param value: string with domain, hostname
        :return: bool
        """

        def to_unicode(obj, charset='utf-8', errors='strict'):
            if obj is None:
                return None
            if not isinstance(obj, bytes):
                return str(obj)
            return obj.decode(charset, errors)

        pattern = re_compile(
            r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
            r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
            r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
            r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
        )

        try:
            result = pattern.match(
                to_unicode(value).encode('idna').decode('ascii'))
            if result:
                return True
            else:
                return False
        except (UnicodeError, AttributeError):
            return False

    def detect_network(input_str: str) -> bool:
        if input_str:
            return any([is_ip(input_str), is_network(input_str)])

    target_type: str = ''
    if detect_url(raw_str):
        target_type = 'url'
    elif detect_domain(raw_str):
        target_type = 'hostname'
    elif detect_network(raw_str):
        target_type = 'network'

    raw_targets = []
    if target_type == 'network':
        raw_targets = ip_network(raw_str, strict=False)
    elif target_type:
        raw_targets = [raw_str]

    if raw_targets:
        for raw_target in raw_targets:
            for target in create_target_http_protocol(str(raw_target), target_settings, target_type):
                yield target
