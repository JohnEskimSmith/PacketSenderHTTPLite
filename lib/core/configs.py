from collections import namedtuple
from dataclasses import dataclass
from typing import List, Dict
CONST_ANY_STATUS = -20000  # no matter what


@dataclass(frozen=True)
class AppConfig:
    senders: int
    total_timeout: int
    queue_sleep: int
    statistics: bool
    input_stdin: str
    single_targets: str
    input_file: str
    output_file: str
    write_mode: str
    show_only_success: bool
    endpoint: str
    status_code: int
    without_base64: bool
    without_certraw: bool
    without_hashs: bool
    proxy_connections: iter
    custom_module: str


@dataclass(frozen=False)
class TargetConfig:
    port: int
    total_timeout: int
    ssl_check: bool
    list_payloads: List[bytes]
    python_payloads: str
    generator_payloads: str
    search_values: List[bytes]
    max_size: int
    headers: Dict
    cookies: Dict
    scheme: str
    endpoint: str
    method: str
    allow_redirects: bool
    hostname: str
    single_payload_type: str

    def as_dict(self):
        return {
            'port': self.port,
            'ssl_check': self.ssl_check,
            'total_timeout': self.total_timeout,
            'list_payloads': self.list_payloads,
            'python_payloads': self.python_payloads,
            'single_payload_type': self.single_payload_type,
            'generator_payloads': self.generator_payloads,
            'endpoint': self.endpoint,
            'hostname': self.hostname,
            'headers': self.headers,
            'cookies': self.cookies,
            'scheme': self.scheme,
            'method': self.method,
            'search_values': self.search_values,
            'max_size': self.max_size,
            'allow_redirects': self.allow_redirects
        }


Target = namedtuple('Target', ['total_timeout',
                               'ssl_check',
                               'list_payloads',
                               'python_payloads',
                               'generator_payloads',
                               'search_values',
                               'endpoint',
                               'max_size',
                               'ip',
                               'hostname',
                               'port',
                               'headers',
                               'cookies',
                               'scheme',
                               'method',
                               'payload',
                               'url',
                               'allow_redirects',
                               'single_payload_type',
                               'additions'])
