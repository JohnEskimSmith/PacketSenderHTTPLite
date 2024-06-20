import asyncio
from base64 import b64encode

# noinspection PyUnresolvedReferences,PyProtectedMember
from ssl import _create_unverified_context as ssl_create_unverified_context

from aiohttp import (
    AsyncResolver,
    ClientSession,
    ClientTimeout,
    TCPConnector,
    TraceConfig,
)
from orjson import dumps as orjson_dumps

from lib.core import (
    Target,
    convert_bytes_to_cert,
    create_error_template,
    create_template_struct,
)
from lib.util import access_dot_path, is_ip, read_http_content
from lib.workers import (
    TargetWorker,
    WrappedResponseClass,
    on_request_end,
    on_request_start,
)

filters_htmls = ["<!DOCTYPE HTML PUBLIC", "<!DOCTYPE html PUBLIC", "<!DOCTYPE html>"]


owowa_versions = [
    {
        "forcedownlevel": 0,
        "username": "NVvDCpIynJau7ZhhjlgvOHRD7icQot3j",
        "password": "InvalidPassword",
        "passwordText": "",
        "isUtf8": 1,
    },
    {
        "forcedownlevel": 0,
        "username": "TJljwYevwsmQf88fXvkei4Ddrl3rZiE3",
        "password": "InvalidPassword",
        "passwordText": "",
        "isUtf8": 1,
    },
]


class CustomWorker(TargetWorker):

    async def do(self, target: Target):
        """
        сопрограмма, осуществляет подключение к Target, отправку и прием данных, формирует результата в виде dict
        """

        def update_line(json_record, target):
            json_record["ip"] = target.ip
            # json_record['ip_v4_int'] = int(ip_address(target.ip))
            # json_record['datetime'] = datetime.datetime.utcnow()
            # json_record['port'] = int(target.port)
            return json_record

        lines = []
        async with self.semaphore:

            timeout = ClientTimeout(total=target.total_timeout)

            # region tmp disable
            trace_config = TraceConfig()
            trace_config.on_request_start.append(on_request_start)
            trace_config.on_request_end.append(on_request_end)
            # endregion
            resolver = AsyncResolver(nameservers=["8.8.8.8", "8.8.4.4"])
            # resolver = None
            # https://github.com/aio-libs/aiohttp/issues/2228  - closed
            if target.ssl_check:

                conn = TCPConnector(
                    ssl=False,
                    family=2,  # need set current family (only IPv4)
                    limit_per_host=0,
                    resolver=resolver,
                )
                session = ClientSession(
                    timeout=timeout,
                    connector=conn,
                    response_class=WrappedResponseClass,
                    trace_configs=[trace_config],
                )
                simple_zero_sleep = 0.250
            else:
                simple_zero_sleep = 0.001
                session = ClientSession(
                    connector=TCPConnector(
                        limit_per_host=0,
                        family=2,  # need set current family (only IPv4)
                        resolver=resolver,
                    ),
                    timeout=timeout,
                    trace_configs=[trace_config],
                )
            selected_proxy_connection = None
            try:
                selected_proxy_connection = next(self.app_config.proxy_connections)
            except:
                pass
            try:
                USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36"
                for i, post_data in enumerate(owowa_versions):
                    result = None
                    if target.ssl_check:
                        post_data["destination"] = f"https://{target.ip}/owa/"
                        url_for_target = f"https://{target.ip}/owa/auth.owa"
                    else:
                        post_data["destination"] = f"http://{target.ip}/owa/"
                        url_for_target = f"http://{target.ip}/owa/auth.owa"
                    owa_headers = {
                        "User-Agent": USER_AGENT,
                        "Accept-Encoding": "gzip, deflate, br",
                        "Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
                        "Cookie": "PrivateComputer=true; PBack=0",
                        "sec-fetch-dest": "document",
                        "sec-fetch-mode": "navigate",
                        "sec-fetch-site": "same-origin",
                        "sec-fetch-user": "?1",
                        "upgrade-insecure-requests": "1",
                        "content-type": "application/x-www-form-urlencoded",
                    }
                    payload = post_data
                    async with session.request(
                        target.method,
                        url_for_target,
                        timeout=timeout,
                        headers=owa_headers,
                        allow_redirects=False,
                        json=payload,
                        proxy=selected_proxy_connection,
                        trace_request_ctx=self.trace_request_ctx,
                    ) as response:
                        if response.status == 200:
                            buffer = b""
                            try:
                                read_c = asyncio.wait_for(
                                    read_http_content(response, n=target.max_size),
                                    timeout=target.total_timeout,
                                )
                                buffer = await read_c
                            except Exception as e:
                                await asyncio.sleep(1)
                            else:
                                response_text = ""
                                if buffer:
                                    try:
                                        response_text = buffer.decode()
                                    except:
                                        pass
                                    if response_text:
                                        if not any(
                                            [x in response_text for x in filters_htmls]
                                        ):
                                            _default_record = create_template_struct(
                                                target
                                            )
                                            if target.ssl_check:
                                                cert = convert_bytes_to_cert(
                                                    response.peer_cert
                                                )
                                                if not self.app_config.without_certraw:
                                                    _default_record["data"]["http"][
                                                        "result"
                                                    ]["response"]["request"]["tls_log"][
                                                        "handshake_log"
                                                    ][
                                                        "server_certificates"
                                                    ][
                                                        "certificate"
                                                    ][
                                                        "raw"
                                                    ] = b64encode(
                                                        response.peer_cert
                                                    ).decode(
                                                        "utf-8"
                                                    )
                                                if cert:
                                                    _default_record["data"]["http"][
                                                        "result"
                                                    ]["response"]["request"]["tls_log"][
                                                        "handshake_log"
                                                    ][
                                                        "server_certificates"
                                                    ][
                                                        "certificate"
                                                    ][
                                                        "parsed"
                                                    ] = cert
                                            _default_record["data"]["http"][
                                                "status"
                                            ] = "success"
                                            _default_record["data"]["http"]["result"][
                                                "response"
                                            ]["status_code"] = 200
                                            _default_record["data"]["http"]["result"][
                                                "response"
                                            ]["infected"] = True
                                            _default_record["data"]["http"]["result"][
                                                "response"
                                            ]["infected_version"] = i
                                            _default_record["data"]["http"]["result"][
                                                "response"
                                            ]["body"] = response_text
                                            _header = {}
                                            for key in response.headers:
                                                _header[
                                                    key.lower().replace("-", "_")
                                                ] = response.headers.getall(key)
                                            _default_record["data"]["http"]["result"][
                                                "response"
                                            ]["headers"] = _header
                                            result = update_line(
                                                _default_record, target
                                            )
                        elif response.status == 302:
                            _default_record = create_template_struct(target)
                            if target.ssl_check:
                                cert = convert_bytes_to_cert(response.peer_cert)
                                if not self.app_config.without_certraw:
                                    _default_record["data"]["http"]["result"][
                                        "response"
                                    ]["request"]["tls_log"]["handshake_log"][
                                        "server_certificates"
                                    ][
                                        "certificate"
                                    ][
                                        "raw"
                                    ] = b64encode(
                                        response.peer_cert
                                    ).decode(
                                        "utf-8"
                                    )
                                if cert:
                                    _default_record["data"]["http"]["result"][
                                        "response"
                                    ]["request"]["tls_log"]["handshake_log"][
                                        "server_certificates"
                                    ][
                                        "certificate"
                                    ][
                                        "parsed"
                                    ] = cert
                            _default_record["data"]["http"]["status"] = "success"
                            _default_record["data"]["http"]["result"]["response"][
                                "status_code"
                            ] = 302
                            _default_record["data"]["http"]["result"]["response"][
                                "infected"
                            ] = False
                            _header = {}
                            for key in response.headers:
                                _header[key.lower().replace("-", "_")] = (
                                    response.headers.getall(key)
                                )
                            _default_record["data"]["http"]["result"]["response"][
                                "headers"
                            ] = _header
                            result = update_line(_default_record, target)
                        else:
                            _default_record = create_template_struct(target)
                            if target.ssl_check:
                                cert = convert_bytes_to_cert(response.peer_cert)
                                if not self.app_config.without_certraw:
                                    _default_record["data"]["http"]["result"][
                                        "response"
                                    ]["request"]["tls_log"]["handshake_log"][
                                        "server_certificates"
                                    ][
                                        "certificate"
                                    ][
                                        "raw"
                                    ] = b64encode(
                                        response.peer_cert
                                    ).decode(
                                        "utf-8"
                                    )
                                if cert:
                                    _default_record["data"]["http"]["result"][
                                        "response"
                                    ]["request"]["tls_log"]["handshake_log"][
                                        "server_certificates"
                                    ][
                                        "certificate"
                                    ][
                                        "parsed"
                                    ] = cert
                            _default_record["data"]["http"]["status"] = "success"
                            _default_record["data"]["http"]["result"]["response"][
                                "status_code"
                            ] = response.status
                            _header = {}
                            for key in response.headers:
                                _header[key.lower().replace("-", "_")] = (
                                    response.headers.getall(key)
                                )
                            _default_record["data"]["http"]["result"]["response"][
                                "headers"
                            ] = _header
                            result = update_line(_default_record, target)

                    if not result:
                        result = create_error_template(
                            target, error_str="", status_string="unknown"
                        )
                    if result:
                        if "duration" in self.trace_request_ctx:
                            request_duration = self.trace_request_ctx["duration"]
                            result["data"]["http"]["duration"] = request_duration
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
                                    line = orjson_dumps(result)
                            else:
                                line = orjson_dumps(result)
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
            except Exception as exp:
                error_str = ""
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
