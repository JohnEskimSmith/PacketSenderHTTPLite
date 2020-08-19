#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "SAI"
__license__ = "GPLv3"
__status__ = "Dev"

from aioconsole import ainput
from ipaddress import ip_address, ip_network
from aiohttp import ClientSession, ClientTimeout, TCPConnector, ClientConnectionError, ClientResponse
from collections import namedtuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import asyncio
import ujson
import base64
from random import choice
from hexdump import hexdump
import argparse
import datetime
import aiofiles
import copy
import os
from hashlib import sha256, sha1, md5
import re
import aiodns
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


from typing import (Any,
                    Callable,
                    Iterable,
                    NamedTuple,
                    Generator,
                    List,
                    BinaryIO,
                    TextIO,
                    )

def check_domain(value) -> bool:
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

    pattern = re.compile(
        r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
        r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
    )

    try:
        result = pattern.match(to_unicode(value).encode('idna').decode('ascii'))
        if result:
            return True
        else:
            return False
    except (UnicodeError, AttributeError):
        return False


def dict_paths(some_dict: dict,
               path: set = ()):
    """
    Итератор по ключам в словаре
    :param some_dict:
    :param path:
    :return:
    """
    for key, value in some_dict.items():
        key_path = path + (key,)
        yield key_path
        if hasattr(value, 'items'):
            yield from dict_paths(value, key_path)


def check_path(some_dict: dict,
               path_sting: str) -> bool:
    """
    Проверяет наличие ключа
    :param some_dict:
    :param path_sting:
    :return:
    """
    if isinstance(some_dict, dict):
        all_paths = set(['.'.join(p) for p in dict_paths(some_dict)])
        if path_sting in all_paths:
            return True


def return_value_from_dict(some_dict: dict,
                           path_string: str) -> Any:
    """
    Возвращает значение ключа в словаре по пути ключа "key.subkey.subsubkey"
    :param some_dict:
    :param path_string:
    :return:
    """
    if check_path(some_dict, path_string):
        keys = path_string.split('.')
        _c = some_dict.copy()
        for k in keys:
            _c = _c[k]
        return _c


def return_user_agent() -> str:
    """
    функция возвращается строку с user-agent
    :return:
    """
    user_agents = ["Mozilla/5.0(Windows NT 10.0;Win64;x64;rv: 59.0) Gecko / 20100101 Firefox / 59.0",
                   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36.",
                   "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0",
                   "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/43.0",
                   "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/41.0",
                   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2704.103 Safari/537.36",
                   'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991',
                   'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 OPR/42.0.2393.94',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 OPR/42.0.2393.94',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36 OPR/47.0.2631.39',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52',
                   'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52',
                   'Mozilla/5.0 (Windows NT 5.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991',
                   'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36 OPR/47.0.2631.39',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36 OPR/52.0.2871.99',
                   'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991',
                   'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991',
                   'Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991',
                   'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 OPR/42.0.2393.94',
                   'Mozilla/5.0 (Windows NT 5.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 OPR/42.0.2393.94',
                   'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 OPR/42.0.2393.94',
                   'Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 OPR/42.0.2393.94',
                   'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36 OPR/52.0.2871.99',
                   'Mozilla/5.0 (Windows NT 6.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36 OPR/47.0.2631.39',
                   'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52',
                   'Mozilla/5.0 (Windows NT 6.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52',
                   'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52',
                   'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52',
                   'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36 OPR/47.0.2631.39',
                   'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36 OPR/47.0.2631.39',
                   'Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14',
                   'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36 OPR/47.0.2631.39',
                   'Mozilla/5.0 (Linux; Android; 4.1.2; GT-I9100 Build/000000) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/25.0.1234.12 Mobile Safari/537.22 OPR/14.0.123.123',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36 OPR/46.0.2597.57',
                   'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36 OPR/52.0.2871.99',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 OPR/32.0.1948.25',
                   'Opera/9.80 (X11; Linux zvav; U; en) Presto/2.12.423 Version/12.16',
                   'Mozilla/5.0 (Windows NT 6.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36 OPR/52.0.2871.99',
                   'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36 OPR/52.0.2871.99',
                   'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36 OPR/52.0.2871.99',
                   'Mozilla/5.0 (Windows NT 5.1; U; en) Opera 8.01',
                   'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36 OPR/36.0.2130.80',
                   'Mozilla/4.0 (compatible; MSIE 6.0; MSIE 5.5; Windows NT 5.0) Opera 7.02 Bork-edition [en]',
                   'Opera/9.80 (Macintosh; Intel Mac OS X 10.10.5) Presto/2.12.388 Version/12.16',
                   'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36 OPR/26.0.1656.60',
                   'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36 OPR/46.0.2597.57',
                   'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.50',
                   'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.1144',
                   'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36 OPR/26.0.1656.60',
                   'Opera/9.80 (X11; Linux zvav; U; en) Presto/2.8.119 Version/11.10',
                   'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41',
                   'Mozilla/5.0 (Linux; U; Android 5.0.2; zh-CN; Redmi Note 3 Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 OPR/11.2.3.102637 Mobile Safari/537.36',
                   'Opera/9.80 (Windows NT 6.2; Win64; x64) Presto/2.12.388 Version/12.15',
                   'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.2743.82 Safari/537.36 OPR/39.0.2256.43',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36 OPR/52.0.2871.64',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
                   'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
                   'Mozilla/5.0 (Linux; Android 4.4.2; XMP-6250 Build/HAWK) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Safari/537.36 ADAPI/2.0 (UUID:9e7df0ed-2a5c-4a19-bec7-2cc54800f99d) RK3188-ADAPI/1.2.84.533 (MODEL:XMP-6250)',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36',
                   'Mozilla/5.0 (Linux; Android 6.0.1; SM-G532G Build/MMB29T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.83 Mobile Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.109 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
                   'Mozilla/5.0 (Linux; Android 6.0; vivo 1713 Build/MRA58K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.124 Mobile Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.63 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36',
                   'Mozilla/5.0 (Linux; Android 7.1; Mi A1 Build/N2G47H) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.83 Mobile Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.65 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
                   'Mozilla/5.0 (Linux; Android 6.0.1; CPH1607 Build/MMB29M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/63.0.3239.111 Mobile Safari/537.36',
                   'Mozilla/5.0 (Linux; Android 5.1; A37f Build/LMY47V) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.93 Mobile Safari/537.36',
                   'Mozilla/5.0 (Linux; Android 6.0.1; vivo 1603 Build/MMB29M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.83 Mobile Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
                   'Mozilla/5.0 (Linux; Android 6.0.1; Redmi 4A Build/MMB29M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.116 Mobile Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.104 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36',
                   'Mozilla/5.0 (Linux; Android 6.0; vivo 1606 Build/MMB29M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.124 Mobile Safari/537.36',
                   'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Mwendo/1.1.5 Safari/537.21',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.7 (KHTML, like Gecko) Version/9.1.2 Safari/601.7.7',
                   'Mozilla/5.0 (iPad; CPU OS 9_3_2 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13F69 Safari/601.1',
                   'Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B143 Safari/601.1',
                   'Mozilla/5.0 (iPad; CPU OS 9_3_5 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13G36 Safari/601.1',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8',
                   'Mozilla/5.0 (iPad; CPU OS 10_2_1 like Mac OS X) AppleWebKit/602.4.6 (KHTML, like Gecko) Version/10.0 Mobile/14D27 Safari/602.1',
                   'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1 Safari/605.1.15',
                   'Mozilla/5.0 (iPhone; CPU iPhone OS 10_2_1 like Mac OS X) AppleWebKit/602.4.6 (KHTML, like Gecko) Version/10.0 Mobile/14D27 Safari/602.1',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/604.5.6 (KHTML, like Gecko) Version/11.0.3 Safari/604.5.6',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/603.2.4 (KHTML, like Gecko) Version/10.1.1 Safari/603.2.4',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/601.4.4 (KHTML, like Gecko) Version/9.0.3 Safari/601.4.4',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/603.1.30 (KHTML, like Gecko) Version/10.1 Safari/603.1.30',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/602.4.8 (KHTML, like Gecko) Version/10.0.3 Safari/602.4.8',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/601.5.17 (KHTML, like Gecko) Version/9.1 Safari/601.5.17',
                   'Mozilla/5.0 (iPhone; CPU iPhone OS 9_3 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13E188a Safari/601.1',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/601.6.17 (KHTML, like Gecko) Version/9.1.1 Safari/601.6.17',
                   'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.0 Mobile/14G60 Safari/602.1',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0.2 Safari/604.4.7',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14',
                   'Mozilla/5.0 (iPhone; CPU iPhone OS 8_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B410 Safari/600.1.4',
                   'Mozilla/5.0 (iPhone; CPU iPhone OS 11_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1',
                   'Mozilla/5.0 (iPhone; CPU iPhone OS 9_3_2 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13F69 Safari/601.1',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Safari/604.1.38',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/601.2.7 (KHTML, like Gecko) Version/9.0.1 Safari/601.2.7',
                   'Mozilla/5.0 (iPhone; CPU iPhone OS 10_2 like Mac OS X) AppleWebKit/602.3.12 (KHTML, like Gecko) Version/10.0 Mobile/14C92 Safari/602.1',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/601.7.8 (KHTML, like Gecko) Version/9.1.3 Safari/537.86.7',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0.1 Safari/604.3.5',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.1 Safari/605.1.15',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
                   'Mozilla/5.0 (iPhone; CPU iPhone OS 9_3_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13E238 Safari/601.1',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_2) AppleWebKit/602.3.12 (KHTML, like Gecko) Version/10.0.2 Safari/602.3.12',
                   'Mozilla/5.0 (iPhone; CPU iPhone OS 9_2_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13D15 Safari/601.1',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/534.59.10 (KHTML, like Gecko) Version/5.1.9 Safari/534.59.10',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.78.2 (KHTML, like Gecko) Version/6.1.6 Safari/537.78.2',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/601.4.4 (KHTML, like Gecko) Version/9.0.3 Safari/601.4.4',
                   'Mozilla/5.0 (iPhone; CPU iPhone OS 10_1_1 like Mac OS X) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0 Mobile/14B100 Safari/602.1',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Safari/605.1.15',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/601.5.17 (KHTML, like Gecko) Version/9.1 Safari/601.5.17',
                   'Mozilla/5.0 (iPhone; CPU iPhone OS 11_2_1 like Mac OS X) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0 Mobile/15C153 Safari/604.1',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.8 (KHTML, like Gecko) Version/9.1.3 Safari/601.7.8',
                   'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_2 like Mac OS X) AppleWebKit/603.2.4 (KHTML, like Gecko) Version/10.0 Mobile/14F89 Safari/602.1',
                   'Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/14A456 Safari/602.1',
                   'Mozilla/5.0 (iPhone; CPU iPhone OS 11_2_6 like Mac OS X) AppleWebKit/604.5.6 (KHTML, like Gecko) Version/11.0 Mobile/15D100 Safari/604.1',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50']
    return choice(user_agents)


def check_ip(ip_str: str) -> bool:
    """
    Проверка строки на ip адрес
    :param ip_str:
    :return:
    """
    try:
        ip_address(ip_str)
        return True
    except:
        return False


def check_network(net_str: str) -> bool:
    """
    Проверка строки на ip адрес сети
    :param net_str:
    :return:
    """
    try:
        ip_network(net_str)
        return True
    except:
        return False


def create_target_http_protocol(hostname: str,
                                settings: dict,
                                domain: bool = False) -> Generator[NamedTuple, None, None]:
    """
    На основании ip адреса и настроек возвращает через yield
    экзэмпляр namedtuple - Target.
    Target содержит всю информацию необходимую для worker.
    :param ip_str:
    :param settings:
    :return:
    """
    current_settings = copy.copy(settings)
    if not settings['full_headers']:
        if settings['user_agent'] == 'random':
            headers = {'user-agent': return_user_agent()}
            current_settings['headers'] = headers
        elif settings['user_agent'].lower() == 'no':
            current_settings['headers'] = {}
        else:
            headers = {'user-agent': settings['user_agent']}
            current_settings['headers'] = headers
    else:
        current_settings['headers'] = settings['full_headers']


    if current_settings['max_size'] != -1:
        current_settings['max_size'] = current_settings['max_size']*1024

    # data.http.result.response.request.url.scheme
    if current_settings['sslcheck']:
        _url = f"https://{hostname}:{str(current_settings['port'])}{current_settings['endpoint']}"
        current_settings['scheme'] = 'https'
    else:
        _url = f"http://{hostname}:{str(current_settings['port'])}{current_settings['endpoint']}"
        current_settings['scheme'] = 'http'
    current_settings['url'] = _url
    current_settings['status_domain'] = domain
    if not domain:
        current_settings['ip'] = hostname
        current_settings['fqdn'] = ''
    else:
        current_settings['ip'] = ''
        current_settings['fqdn'] = hostname

    key_names = list(current_settings.keys())
    key_names.extend(['payload'])
    Target = namedtuple('Target', key_names)
    if payloads:
        for payload in payloads:
            tmp_settings = copy.copy(current_settings)
            tmp_settings['payload'] = payload
            target = Target(**tmp_settings)
            yield target
    else:
        current_settings['payload'] = None
        target = Target(**current_settings)
        yield target


def create_targets_http_protocol(ip_str: str,
                                 settings: dict,
                                 domain: bool = False) -> NamedTuple:
    if not domain:
        hosts = ip_network(ip_str, strict=False)
    else:
        hosts = [ip_str]

    for host in hosts:
        for target in create_target_http_protocol(str(host), settings, domain=domain):
            yield target



def create_template_struct(target: NamedTuple) -> dict:
    """
    такая структура у результатов в модуле zgrab2 http - поэтому ее так и повторил
    :return:
    """

    result = {'data':
                  {'http':
                       {'status': 'http',
                        'result':
                            {'response':
                                 {'request':{}
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
    if target.sslcheck:
        result['data']['http']['result']['response']['request'].update(_tls_log)
    result['data']['http']['result']['response']['request']['url'] = {}
    result['data']['http']['result']['response']['request']['url']['scheme'] = target.scheme
    if len(target.fqdn) > 0:
        result['data']['http']['result']['response']['request']['url']['host'] = target.fqdn
        result['host'] = target.fqdn
        result['data']['http']['result']['response']['request']['host'] = target.fqdn
    elif len(target.ip) > 0:
        result['data']['http']['result']['response']['request']['url']['host'] = target.ip
        result['data']['http']['result']['response']['request']['host'] = target.ip
    result['data']['http']['result']['response']['request']['url']['path'] = target.endpoint
    result['data']['http']['result']['response']['request']['method'] = target.method
    return result


def create_template_error(target, error_str):
    _tmp = {'ip': target.ip,
            'port': target.port,
            'host': target.fqdn,
            'data': {}}
    _tmp["data"]["http"] = {}
    _tmp["data"]["http"]["status"] = "unknown-error"
    _tmp["data"]["http"]["error"] = error_str
    if not (len(target.fqdn) > 0):
        _tmp.pop('host')
    if not (len(target.ip) > 0):
        _tmp.pop('ip')
    return _tmp


async def readcontent(self, n: int=-1) -> bytes:
    """Read up to 'n' bytes of the response payload.

    If 'n' is -1 (default), read the entire payload.
    """
    if self._body is None:
        try:
            if n == -1:
                self._body = await self.content.read()
            else:
                chunks = []
                i = 0
                while i < n:
                    chunk = await self.content.read(n=n - i)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    i += len(chunk)

                self._body = b''.join(chunks)

            for trace in self._traces:
                await trace.send_response_chunk_received(self._body)

        except BaseException:
            self.close()
            raise
    elif self._released:
        raise ClientConnectionError('Connection closed')
    return self._body


def convert_bytes_to_cert(bytes_cert):
    cert = None
    try:
        cert = x509.load_der_x509_certificate(bytes_cert, default_backend())
    except:
        try:
            cert = x509.load_pem_x509_certificate(bytes_cert, default_backend())
        except:
            pass

    if cert:
        try:
            alg_hash_name = cert.signature_hash_algorithm.name
            alg_hash = cert.signature_hash_algorithm
            tp = cert.fingerprint(alg_hash)
            alg_hash_value = ''.join('{:02x}'.format(x) for x in tp)
        except:
            pass


        # region block not used
        # signature_hash_algorithm = cert.signature_hash_algorithm
        # subject = cert.subject
        # not_valid_after = cert.not_valid_after
        # alg_hash = cert.signature_hash_algorithm
        # tp = cert.fingerprint(alg_hash)
        # alg_hash_value = ''.join('{:02x}'.format(x) for x in tp)
        # endregion

        result = dict()
        serial_number = cert.serial_number
        issuer = cert.issuer
        try:
            result['validity'] = {}
            result['validity']['end_datetime'] = cert.not_valid_after
            result['validity']['start_datetime'] = cert.not_valid_before
            result['validity']['end'] = result['validity']['end_datetime'].strftime('%Y-%m-%dT%H:%M:%SZ')
            result['validity']['start'] = result['validity']['start_datetime'].strftime('%Y-%m-%dT%H:%M:%SZ')
        except Exception as e:
            pass
        result['issuer'] = {}
        dict_replace = {'countryName': 'country',
                        'organizationName': 'organization',
                        'commonName': 'common_name'}
        try:
            for n in issuer.rdns:
                z = n._attributes[0]
                name_k = z.oid._name
                value = z.value
                if name_k in dict_replace:
                    result['issuer'][dict_replace[name_k]] = [value]
        except Exception as e:
            pass
        try:
            if 'v' in cert.version.name:
                result['version'] = cert.version.name.split('v')[1].strip()
        except:
            result['version'] = str(cert.version.value)
        dnss = get_certificate_domains(cert)
        atr = cert.subject._attributes
        result['subject'] = {}
        for i in atr:
            for q in i._attributes:
                result['subject'][q.oid._name] = [q.value]
        if 'serialNumber' in list(result.keys()):
            if len(result['serialNumber']) == 16:
                result['serialNumber'] = '00' + result['serialNumber']
        try:
            result['serialNumber_int'] = int('0x' + result['serialNumber'], 16)
            result['serial_number'] = str(result['serialNumber_int'])
        except:
            result['serialNumber_int'] = 0
        result['names'] = dnss
        if result['serialNumber_int'] == 0:
            result['serial_number'] = str(serial_number)
            result['serial_number_hex'] = str(hex(serial_number))
        result['raw_serial'] = str(serial_number)
        # result['fingerprint_sha256'] = alg_hash_value
        hashs = {'fingerprint_sha256': sha256,
                 'fingerprint_sha1': sha1,
                 'fingerprint_md5': md5
                 }
        for namehash, func in hashs.items():
            hm = func()
            hm.update(bytes_cert)
            result[namehash] = hm.hexdigest()
        remove_keys = ['serialNumber_int']
        for key in remove_keys:
            result.pop(key)
        return result


def get_certificate_domains(cert):
    """
    Gets a list of all Subject Alternative Names in the specified certificate.
    """
    try:
        for ext in cert.extensions:
            ext = ext.value
            if isinstance(ext, x509.SubjectAlternativeName):
                return ext.get_values_for_type(x509.DNSName)
    except:
        return []


class WrappedResponseClass(ClientResponse):

    def __init__(self, *args, **kwargs):
        super(WrappedResponseClass, self).__init__(*args, **kwargs)
        self._peer_cert = None
        self._ssl_prot = None
        self._ssl_prot_extra = None

    async def start(self, connection, read_until_eof=False):
        try:
            self._ssl_prot = connection.transport._ssl_protocol
            self._ssl_prot_extra = self._ssl_prot._extra
            if self._ssl_prot_extra:
                self._peer_cert = self._ssl_prot_extra['ssl_object'].getpeercert(binary_form=True)
        except Exception as e:
            print(str(e))
        finally:
            bs = super(WrappedResponseClass, self)
            return await bs.start(connection)

    @property
    def peer_cert(self):
        return self._peer_cert

    @property
    def ssl_prot(self):
        return self._ssl_prot

    @property
    def ssl_extra(self):
        return self._ssl_prot_extra


async def make_document_from_response(response, target) -> dict:

    def update_line(json_record, target):
        json_record['ip'] = target.ip
        # json_record['ip_v4_int'] = int(ip_address(target.ip))
        # json_record['datetime'] = datetime.datetime.utcnow()
        # json_record['port'] = int(target.port)
        return json_record

    _default_record = create_template_struct(target)
    if target.sslcheck:
        cert = convert_bytes_to_cert(response.peer_cert)
        _default_record['data']['http']['result']['response']['request']['tls_log']['handshake_log'][
            'server_certificates']['certificate']['raw'] = base64.b64encode(response.peer_cert).decode('utf-8')
        if cert:
            _default_record['data']['http']['result']['response']['request']['tls_log']['handshake_log'][
                'server_certificates']['certificate']['parsed'] = cert


    _default_record['data']['http']['status'] = "success"
    _default_record['data']['http']['result']['response']['status_code'] = response.status
    _header = {}

    for key in response.headers:
        _header[key.lower().replace('-', '_')] = response.headers.getall(key)
    _default_record['data']['http']['result']['response']['headers']=_header
    if target.method in ['GET', 'POST', 'PUT', 'DELETE', 'UPDATE']:

        buffer = b""
        try:
            buffer = await readcontent(response, n=target.max_size)
        except Exception as e:
            pass

        _default_record['data']['http']['result']['response']['content_length'] = len(buffer)
        _default_record['data']['http']['result']['response']['body'] = ''
        try:
            _default_record['data']['http']['result']['response']['body'] = buffer.decode()
        except Exception as e:
            pass
        #
        try:
            _base64_data = base64.b64encode(buffer).decode('utf-8')
            _default_record['data']['http']['result']['response']['body_raw'] =_base64_data
        except Exception as e:
            pass
        try:
            hashs = {'sha256':sha256,
                     'sha1': sha1,
                     'md5': md5}
            for namehash, func in hashs.items():
                hm = func()
                hm.update(buffer)
                _default_record['data']['http']['result']['response'][f'body_{namehash}'] = hm.hexdigest()
        except Exception as e:
            pass
        _default_record['data']['http']['result']['response']['body_hexdump'] = ''
        try:
            hdump = hexdump(buffer, result='return')
            _output = base64.b64encode(bytes(hdump, 'utf-8'))
            output = _output.decode('utf-8')
            _default_record['data']['http']['result']['response']['body_hexdump'] = output
        except Exception as e:
            pass
    result_to_output = update_line(_default_record, target)
    return result_to_output


async def worker_single(target):

    def return_ip_from_deep(sess, response) -> str:
        try:
            ip_port = response.connection.transport.get_extra_info('peername')
            if check_ip(ip_port[0]):
                return ip_port[0]
        except:
            pass
        try:
            _tmp_conn_key = sess.connector._conns.items()
            for k, v in _tmp_conn_key:
                _h = v[0][0]
                ip_port = _h.transport.get_extra_info('peername')
                if check_ip(ip_port[0]):
                    return ip_port[0]
        except:
            pass
        return ''

    result = None
    timeout = ClientTimeout(target.timeout)
    if target.sslcheck:
        conn = TCPConnector(ssl=False, limit_per_host=1)
        session = ClientSession(timeout=timeout, connector=conn,  response_class=WrappedResponseClass)
    else:
        session = ClientSession(timeout=timeout)
    try:

        # files = {'file': open('payload', 'rb')}
        # async with session.request(target.method,
        #                            target.url,
        #                            allow_redirects=target.allow_redirects,
        #                            data=files) as response:
        # https: // docs.aiohttp.org / en / stable / client_quickstart.html  # post-a-multipart-encoded-file
        async with session.request(target.method,
                                   target.url,
                                   headers=target.headers,
                                   allow_redirects=target.allow_redirects,
                                   data=target.payload,
                                   timeout=timeout) as response:
            result = await make_document_from_response(response, target)
            # какое-то безумие с функцией return_ip_from_deep, автор aiohttp говорит, что просто так до ip сервера
            # не добраться
            # link: https://github.com/aio-libs/aiohttp/issues/4249
            # но есть моменты....
            # в функции return_ip_from_deep через какую-то "жопу" добираемся до ip - это не дело, но пока оставим так
            if len(result['ip']) == 0:
                _ip = return_ip_from_deep(session, response)
                result['ip'] = _ip
        await asyncio.sleep(0.05)
        await session.close()
    except Exception as e:
        result = create_template_error(target, str(e))
        await asyncio.sleep(0.05)
        await session.close()
    return result


async def worker_group(block: list):
    global count_good
    global count_error
    tasks = []
    for target in block:
        task = asyncio.ensure_future(worker_single(target))
        tasks.append(task)
    responses = await asyncio.gather(*tasks)  # all response bodies in this variable - responses
    await asyncio.sleep(0.05)
    if responses:
        method_write_result = write_to_stdout
        if mode_write == 'a':
            method_write_result = write_to_file
        async with aiofiles.open(output_file, mode=mode_write) as file_with_results:
            for dict_line in responses:
                if dict_line:
                    success = return_value_from_dict(dict_line, "data.http.status")
                    if success == "success":
                        count_good += 1
                    else:
                        count_error += 1
                    line = None
                    try:
                        if args.show_only_success:
                            if success == "success":
                                line = ujson.dumps(dict_line)
                        else:
                            line = ujson.dumps(dict_line)
                    except Exception as e:
                        pass
                    if line:
                        await method_write_result(file_with_results, line)


async def write_to_stdout(object_file: BinaryIO,
                          record_str: str):
    try:
        await object_file.write(record_str.encode('utf-8') + b'\n')
    except Exception as e:
        pass

async def write_to_file(object_file: TextIO,
                        record_str: str):
    try:
        await object_file.write(record_str + '\n')
    except Exception as e:
        pass


async def work_with_queue(queue_results, count):

    count_elements = 0
    block = []

    while True:
        # wait for an item from the "start_application"
        item = await queue_results.get()
        if item == b"check for end":
            # TODO send statistics
            break
        if item:
            block.append(item)
            count_elements += 1
            if count_elements % (int(count)) == 0:
                # TODO rethink structures
                await worker_group(block)
                del block
                block = []
                await asyncio.sleep(0.2)  # magic number :)

    if block:
        await worker_group(block)


async def read_input_file(queue_results, settings, path_to_file):
    global count_input
    async with aiofiles.open(path_to_file, mode='rt') as f: # read str
        async for line in f:
            linein = line.strip()
            targets = None
            if any([check_ip(linein), check_network(linein)]):
                targets = create_targets_http_protocol(linein, settings)
            elif check_domain(linein):
                targets = create_targets_http_protocol(linein, settings, domain=True)
            if targets:
                for target in targets:
                    count_input += 1 # statistics
                    queue_results.put_nowait(target)
    queue_results.put_nowait(b"check for end")


async def read_input_stdin(queue_results, settings, path_to_file=None):
    global count_input
    while True:
        try:
            _tmp_input = await ainput()  # read str from stdin
            linein = _tmp_input.strip()
            targets = None
            if any([check_ip(linein), check_network(linein)]):
                targets = create_targets_http_protocol(linein, settings)
            elif check_domain(linein):
                targets = create_targets_http_protocol(linein, settings, domain=True)
            if targets:
                for target in targets:
                    count_input += 1  # statistics
                    queue_results.put_nowait(target)
        except EOFError:
            queue_results.put_nowait(b"check for end")
            break


def checkfile(path_to_file):
    return os.path.isfile(path_to_file)


def parse_payloads_files(payload_files:list):
    result = [path_to_file for path_to_file in payload_files if checkfile(path_to_file)]
    return result


def return_payloads_from_files(payload_files:list):
    payloads = []
    files = parse_payloads_files(payload_files)
    for payloadfile in files:
        with open(payloadfile, 'rb') as f:
            payload = f.read()
            payloads.append(payload)
    return payloads


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='HTTP(s) sender(asyncio)')
    parser.add_argument("-settings", type=str, help="path to file with settings(yaml)")

    parser.add_argument("-f", "--input-file", dest='input_file', type=str, help="path to file with targets")

    parser.add_argument("-o", "--output-file", dest='output_file', type=str, help="path to file with results")

    parser.add_argument("-s", "--senders",  dest='senders', type=int,
                        default=1024, help='Number of coroutines to use (default: 1024)')

    parser.add_argument("--max-size", dest='max_size', type=int,
                        default=256, help='Maximum total kilobytes to read for a single host (default 256)')

    parser.add_argument("-t", "--timeout", dest='timeout', type=int,
                        default=15, help='Set connection timeout (default: 15)')

    parser.add_argument("-p", "--port", type=int, default=80, help='Specify port (default: 80) '
                                                                   'or ports range (nmap syntax: eg 1,2-10,11)')

    parser.add_argument("--endpoint", type=str,
                        default='/', help="Send an HTTP request to an endpoint (default: /)")

    parser.add_argument("--user-agent", dest='user_agent', type=str, default='random',
                        help='Set a custom user agent (default: randomly selected from popular well-known agents)')

    parser.add_argument("--allow-redirects", dest='allow_redirects', action='store_true')

    parser.add_argument("--method", type=str, default="GET",
                        help='Set HTTP request method type (default: GET, available methods: GET, POST, HEAD)')

    parser.add_argument('--use-https', dest='sslcheck', action='store_true',
                        help='Perform an HTTPS connection on the initial host')

    parser.add_argument('--list-payloads', nargs='*', dest='list_payloads',
                        help='list payloads(bytes stored in files): file1 file2 file2', required=False)

    parser.add_argument('--full-headers', dest='full_headers', type=str, default=None)

    parser.add_argument('--show-statistics', dest='statistics', action='store_true')

    parser.add_argument('--show-only-success', dest='show_only_success', action='store_true')


    path_to_file_targets = None # set default None to inputfile
    args = parser.parse_args()

    if args.settings:
        pass # TODO read from yaml
    else:
        # region parser ARGs
        if not args.input_file:
            method_create_targets = read_input_stdin # set method - async read from stdin (str)
        else:
            method_create_targets = read_input_file # set method - async read from file(txt, str)

            path_to_file_targets = args.input_file
            if not checkfile(path_to_file_targets):
                print(f'ERROR: file not found: {path_to_file_targets}')
                exit(1)

        if not args.output_file:
            output_file, mode_write = '/dev/stdout', 'wb'
        else:
            output_file, mode_write = args.output_file, 'a'

        if args.list_payloads and args.method != 'POST':
            print('Exit, method not POST, why payloads is needed ?')
            exit(1)

        payloads = None
        if args.list_payloads:
            payloads = return_payloads_from_files(args.list_payloads)

        method_query = (args.method).upper()


        # endregion
    full_headers = None
    if args.full_headers:
        try:
            full_headers = ujson.loads(args.full_headers)
        except Exception as e:
            print(f'errors with full headers. {e}')

    settings = {'port': args.port,
               'endpoint': args.endpoint,
               'sslcheck': args.sslcheck,
               'timeout': args.timeout,
               'method': method_query,
               'allow_redirects': args.allow_redirects,
               'user_agent': args.user_agent,
               'list_payloads': payloads,
               'max_size': args.max_size,
               'full_headers': full_headers
                }

    count_cor = args.senders

    count_input = 0
    count_good = 0
    count_error = 0
    start_time = datetime.datetime.now()

    loop = asyncio.get_event_loop()
    queue_results = asyncio.Queue()

    s = datetime.datetime.now()
    resolver = aiodns.DNSResolver(loop=loop)
    producer_coro = method_create_targets(queue_results, settings, path_to_file_targets)
    consumer_coro = work_with_queue(queue_results, count_cor)
    loop.run_until_complete(asyncio.gather(producer_coro, consumer_coro))
    loop.close()

    stop_time = datetime.datetime.now()
    _delta_time = stop_time-start_time
    duration_time_sec = _delta_time.total_seconds()
    if args.statistics:
        statistics = {'duration': duration_time_sec,
                      'valid targets': count_input,
                      'success': count_good,
                      'fails': count_error}
        print(ujson.dumps(statistics))