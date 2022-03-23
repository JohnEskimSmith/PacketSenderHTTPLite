from lib.workers import TargetWorker, on_request_end, on_request_start, WrappedResponseClass
from lib.core import create_error_template, Target
import abc
import asyncio
from re import findall
from abc import ABC
from asyncio import Queue
from base64 import b64encode
from hashlib import sha256, sha1, md5
# noinspection PyUnresolvedReferences,PyProtectedMember
from ssl import _create_unverified_context as ssl_create_unverified_context
from typing import Optional, Callable, Any, Coroutine, Dict
from aiohttp import ClientSession, ClientTimeout, TCPConnector, ClientResponse, TraceConfig, AsyncResolver
from aioconsole import ainput
from aiofiles import open as aiofiles_open
from ujson import dumps as ujson_dumps
from lib.core import create_template_struct, convert_bytes_to_cert, create_error_template, Stats, AppConfig, \
    Target, TargetConfig, CONST_ANY_STATUS
from lib.util import access_dot_path, is_ip, filter_bytes, write_to_file, write_to_stdout, read_http_content
from urllib.parse import urljoin
import abc
import asyncio
from abc import ABC
from asyncio import Queue
from base64 import b64encode

import asyncio

from pathlib import Path
from typing import Dict

class CustomWorker(TargetWorker):
    async def do(self, target: Target):
        def return_ip_from_deep(sess, response) -> str:
            try:
                ip_port = response.connection.transport.get_extra_info('peername')
                if is_ip(ip_port[0]):
                    return ip_port[0]
            except BaseException:
                pass
            try:
                _tmp_conn_key = sess.connector._conns.items()
                for k, v in _tmp_conn_key:
                    _h = v[0][0]
                    ip_port = _h.transport.get_extra_info('peername')
                    if is_ip(ip_port[0]):
                        return ip_port[0]
            except BaseException:
                pass
            return ''

        def update_line(json_record, target):
            json_record['ip'] = target.ip
            # json_record['ip_v4_int'] = int(ip_address(target.ip))
            # json_record['datetime'] = datetime.datetime.utcnow()
            # json_record['port'] = int(target.port)
            return json_record

        async with self.semaphore:
            result = None
            timeout = ClientTimeout(total=target.total_timeout)

            # region tmp disable
            trace_config = TraceConfig()
            trace_config.on_request_start.append(on_request_start)
            trace_config.on_request_end.append(on_request_end)
            # endregion
            resolver = AsyncResolver(nameservers=['8.8.8.8', '8.8.4.4'])
            # resolver = None
            # https://github.com/aio-libs/aiohttp/issues/2228  - closed
            if target.ssl_check:

                conn = TCPConnector(ssl=False,
                                    family=2, # need set current family (only IPv4)
                                    limit_per_host=0,
                                    resolver=resolver)
                session = ClientSession(
                    timeout=timeout,
                    connector=conn,
                    response_class=WrappedResponseClass,
                    trace_configs=[trace_config])
                simple_zero_sleep = 0.250
            else:
                simple_zero_sleep = 0.001
                session = ClientSession(connector=TCPConnector(limit_per_host=0,
                                                               family=2,  # need set current family (only IPv4)
                                                               resolver=resolver),
                                        timeout=timeout,
                                        trace_configs=[trace_config])
            selected_proxy_connection = None
            try:
                selected_proxy_connection = next(self.app_config.proxy_connections)
            except:
                pass
            # step 1
            url_step1 = urljoin(target.url, '/owa/')
            exchange_version = None
            try:
                async with session.request(target.method,
                                           url_step1,
                                           timeout=timeout,
                                           headers=target.headers,
                                           cookies=target.cookies,
                                           allow_redirects=target.allow_redirects,
                                           data=target.payload,
                                           proxy=selected_proxy_connection,
                                           trace_request_ctx=self.trace_request_ctx) as response:
                    _default_record = create_template_struct(target)
                    if target.ssl_check:
                        cert = convert_bytes_to_cert(response.peer_cert)
                        if not self.app_config.without_certraw:
                            _default_record['data']['http']['result']['response']['request']['tls_log']['handshake_log'][
                                'server_certificates']['certificate']['raw'] = b64encode(response.peer_cert).decode(
                                'utf-8')
                        if cert:
                            _default_record['data']['http']['result']['response']['request']['tls_log'][
                                'handshake_log']['server_certificates']['certificate']['parsed'] = cert
                    _default_record['data']['http']['status'] = "success"
                    _default_record['data']['http']['result']['response']['status_code'] = response.status
                    # region
                    _header = {}
                    for key in response.headers:
                        _header[key.lower().replace('-', '_')] = response.headers.getall(key)
                    _default_record['data']['http']['result']['response']['headers'] = _header
                    _tmp_headers = ujson_dumps(_default_record['data']['http']['result']['response']['headers'])
                    if 'X-OWA-Version'.lower().replace('-', '_') in _tmp_headers:
                        exchange_version = response.headers['X-OWA-Version']
                if not exchange_version:
                    _value_sub_url = target.url[8:-1]
                    url_step2 = f'{target.url[:-1]}/owa/auth/logon.aspx?' \
                                f'replaceCurrent=1&url=https%3a%2f%2f{_value_sub_url}%2fowa'
                    async with session.request(target.method,
                                               url_step2,
                                               timeout=timeout,
                                               headers=target.headers,
                                               cookies=target.cookies,
                                               allow_redirects=target.allow_redirects,
                                               data=target.payload,
                                               proxy=selected_proxy_connection,
                                               trace_request_ctx=self.trace_request_ctx) as response:
                        if target.method in ['GET', 'POST', 'PUT', 'DELETE', 'UPDATE']:
                            buffer = b""
                            try:
                                read_c = asyncio.wait_for(read_http_content(response, n=target.max_size),
                                                          timeout=target.total_timeout)
                                buffer = await read_c
                            except Exception as e:
                                pass
                            else:
                                response_test = buffer.decode()
                                exchange_version = findall('<link\s[^>]*href="/owa/[^"]*?([\d.]+)/themes/resources/favicon.ico',
                                                           response_test)
                                if exchange_version:
                                    exchange_version = exchange_version[0]
                if exchange_version:
                    part_list = exchange_version.split('.')
                    if len(part_list) != 4:
                        url_step3 = f'{target.url[:-1]}/ecp/Current/exporttool/' \
                                    'microsoft.exchange.ediscovery.exporttool.application'
                        async with session.request(target.method,
                                                   url_step3,
                                                   timeout=timeout,
                                                   headers=target.headers,
                                                   cookies=target.cookies,
                                                   allow_redirects=target.allow_redirects,
                                                   data=target.payload,
                                                   proxy=selected_proxy_connection,
                                                   trace_request_ctx=self.trace_request_ctx) as response:
                            if response.status == 200:
                                if target.method in ['GET', 'POST', 'PUT', 'DELETE', 'UPDATE']:
                                    buffer = b""
                                    try:
                                        read_c = asyncio.wait_for(read_http_content(response, n=target.max_size),
                                                                  timeout=target.total_timeout)
                                        buffer = await read_c
                                    except Exception as e:
                                        pass
                                    else:
                                        response_test = buffer.decode()
                                        new_version = findall(
                                            r'name=\"microsoft.exchange.ediscovery.exporttool.application\" '
                                            r'version=\"([\d.]+)\"',
                                            response_test
                                        )
                                        if new_version:
                                            exchange_version = new_version[0]
                if exchange_version:
                    _default_record['data']['http']['result']['response']['proxylogon'] = exchange_version
                    _default_record['data']['http']['status'] = 'success'
                    result = update_line(_default_record, target)
                else:
                    result = create_error_template(target, error_str='', status_string='success-not-contain')
                if result:
                    if not result['ip']:
                        result['ip'] = return_ip_from_deep(session, response)
            except Exception as exp:
                error_str = ''
                try:
                    error_str = exp.strerror
                except:
                    pass
                result = create_error_template(target, error_str, type(exp).__name__)
                await asyncio.sleep(simple_zero_sleep)
                try:
                    await session.close()
                except:
                    pass
                try:
                    await conn.close()
                except:
                    pass
            if result:
                if 'duration' in self.trace_request_ctx:
                    request_duration = self.trace_request_ctx['duration']
                    result['data']['http']['duration'] = request_duration
                success = access_dot_path(result, "data.http.status")
                if self.stats:
                    if success == "success":
                        self.stats.count_good += 1
                    else:
                        self.stats.count_error += 1
                line = None
                try:
                    if self.success_only:
                        if success == "success":
                            line = ujson_dumps(result)
                    else:
                        line = ujson_dumps(result)
                except Exception:
                    pass
                if line:
                    await self.output_queue.put(line)
            await asyncio.sleep(simple_zero_sleep)
            try:
                await session.close()
            except:
                pass
            try:
                await conn.close()
            except:
                pass


