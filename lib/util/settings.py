import argparse
import importlib
from hashlib import md5 as haslib_md5
from itertools import cycle
from os import path
from pathlib import Path
from random import choice
from shutil import copy as shutil_copy
from sys import stderr
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from aiofiles import open as aiofiles_open
from aiohttp import BasicAuth
from aiohttp import ClientSession as aiohttp_ClientSession
from orjson import loads as orjson_loads

from lib.core import (
    CONST_ANY_STATUS,
    AppConfig,
    TargetConfig,
    return_payloads_from_files,
)

from .io import decode_base64_string
from .net import is_ip

__all__ = [
    "parse_args",
    "parse_settings",
    "check_config_url",
    "download_module",
    "load_custom_worker",
]

NAME_CUSTOM_WORKER_CLASS = "CustomWorker"
DEFAULT_NAME_SERVERS = "8.8.8.8,8.8.4.4"


def parse_args(custom_args: Optional[List[str]] = None):

    parser = argparse.ArgumentParser(description="HTTP(s) sender lite(asyncio)")
    parser.add_argument("-settings", type=str, help="path to file with settings (yaml)")
    parser.add_argument(
        "--stdin",
        dest="input_stdin",
        action="store_true",
        help="Read targets from stdin",
    )
    parser.add_argument(
        "-t",
        "--targets",
        nargs="+",
        type=str,
        default="",
        dest="single_targets",
        help="Single targets: ipv4, CIDRs, urls",
    )
    parser.add_argument(
        "-f", "--input-file", type=str, help="path to file with targets"
    )
    parser.add_argument(
        "-o", "--output-file", type=str, help="path to file with results"
    )
    parser.add_argument(
        "-s",
        "--senders",
        type=int,
        default=1024,
        help="Number of send coroutines to use (default: 1024)",
    )
    parser.add_argument("--use-uvloop", action="store_true")
    parser.add_argument("--delete-custom", action="store_true")  # TODO: rethink
    parser.add_argument(
        "--queue-sleep",
        type=int,
        default=1,
        help="Sleep duration if the queue is full, default 1 sec. Queue size == senders",
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=1024,
        help="Maximum total bytes(!) to read for a single host (default 1024)",
    )

    parser.add_argument(
        "--timeout",
        dest="total_timeout",
        type=int,
        default=5,
        help="total timeout, seconds (default: 5)",
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="Specify port (default: 80)",
        default=80,
        required=True,
    )
    parser.add_argument(
        "--endpoint",
        type=str,
        default="/",
        help="Send an HTTP request to an endpoint (default: /)",
    )
    parser.add_argument("--use-https", dest="ssl_check", action="store_true")
    parser.add_argument(
        "--dns-servers",
        type=str,
        default=DEFAULT_NAME_SERVERS,
        help=f"set dns as IPv4 with comma. Default: {DEFAULT_NAME_SERVERS}",
    )
    parser.add_argument(
        "--user-agent",
        type=str,
        default="random",
        help="Set a custom user agent (default: randomly selected from popular well-known agents)",
    )
    parser.add_argument("--allow-redirects", action="store_true")
    parser.add_argument(
        "--method",
        type=str,
        default="GET",
        help="Set HTTP request method type (default: GET, available methods: GET, POST, HEAD)",
    )

    # region about proxy
    parser.add_argument(
        "--proxy",
        type=str,
        dest="proxy_connection_string",
        help='proxy connection strings(;): "http://myproxy.com" or "http://user:pass@some.proxy.com"',
    )
    parser.add_argument(
        "--proxy-generator",
        type=str,
        dest="proxy_connection_generator",
        help="not implemented ",
    )
    parser.add_argument("--proxy-source", type=str, help="not implemented")
    # endregion
    # region add custom worker
    parser.add_argument(
        "--module",
        dest="custom_module",
        type=str,
        default="default",
        help="set custom module(from modules)",
    )

    parser.add_argument(
        "--url-module",
        dest="url_custom_module",
        type=str,
        help="set url for download custom module",
    )

    # endregion
    # region add options
    parser.add_argument("--without-base64", action="store_true")
    parser.add_argument("--without-hashs", action="store_true")
    parser.add_argument("--without-cert", dest="without_certraw", action="store_true")
    parser.add_argument("--full-headers", type=str, default=None, help="JSON as string")
    # TODO: &
    parser.add_argument(
        "--full-headers-base64", type=str, default=None, help="not implemented"
    )

    parser.add_argument("--full-headers-hex", type=str, default=None)
    parser.add_argument(
        "--full-cookies", type=str, default=None, help="http cookies as json string"
    )

    parser.add_argument(
        "--full-cookies-hex",
        dest="full_cookies_hex",
        type=str,
        default=None,
        help="http cookies as json string(hex)",
    )
    # endregion

    # region filters
    parser.add_argument(
        "--single-contain",
        type=str,
        help="trying to find a substring in a response(set in base64)",
    )
    parser.add_argument(
        "--single-contain-hex",
        type=str,
        help="trying to find a substring in a response bytes (set in bytes(hex))",
    )
    parser.add_argument(
        "--single-contain-string",
        type=str,
        help="trying to find a substring in a response(set in str)",
    )
    parser.add_argument(
        "--status-code",
        type=int,
        default=CONST_ANY_STATUS,
        help="http status code, ex.: 200, 404",
    )

    parser.add_argument("--show-only-success", action="store_true")
    # endregion
    parser.add_argument(
        "--list-payloads",
        nargs="*",
        dest="list_payloads",
        help="list payloads(bytes stored in files): file1 file2 file2",
        required=False,
    )
    parser.add_argument(
        "--single-payload", type=str, help="single payload in BASE64 from bytes"
    )
    parser.add_argument(
        "--single-payload-hex", type=str, help="single payload in hex(bytes)"
    )
    parser.add_argument(
        "--single-payload-pickle-hex",
        type=str,
        help="python pickle object in hex(bytes)",
    )
    parser.add_argument(
        "--single-payload-type",
        type=str,
        default="DATA",
        help="single payload type: DATA(raw bin), JSON, "
        "FILES(like at requests - Dictionary of 'filename': file-like-objects for multipart encoding upload)",
    )

    parser.add_argument("--python-payloads", type=str, help="path to Python module")
    parser.add_argument(
        "--generator-payloads",
        type=str,
        help="name function of gen.payloads from Python module",
    )
    parser.add_argument("--show-statistics", action="store_true")
    return parser.parse_args(custom_args)


# noinspection PyBroadException
def parse_settings(args: argparse.Namespace) -> Tuple[TargetConfig, AppConfig]:
    if args.settings:
        return parse_settings_file(args.settings)

    if not args.input_stdin and not args.input_file and not args.single_targets:
        print(
            """errors, set input source:
         --stdin read targets from stdin;
         -t,--targets set targets, see -h;
         -f,--input-file read from file with targets, see -h"""
        )
        exit(1)

    payloads = []
    search_values = []
    input_file = None

    if args.input_file:
        input_file = args.input_file
        if not path.isfile(input_file):
            abort(f"ERROR: file not found: {input_file}")

    if not args.output_file:
        output_file, write_mode = "/dev/stdout", "wb"
    else:
        output_file, write_mode = args.output_file, "a"

    if args.list_payloads:
        payloads = list(return_payloads_from_files(args.list_payloads))
    # endregion

    # region about proxy
    proxy_connections = []
    if args.proxy_connection_string:
        # TODO: валидировать строку подключения
        proxy_connection_string = [
            connection
            for connection in args.proxy_connection_string.split(";")
            if connection
        ]
        proxy_connections.extend(proxy_connection_string)
    if proxy_connections:
        proxy_connections = cycle(proxy_connections)
    # endregion

    if args.single_contain:
        try:
            search_value = decode_base64_string(args.single_contain)
            assert search_value is not None
            search_values.append(search_value)
        except Exception as e:
            abort("errors with --single-contain options", e)
    elif args.single_contain_string:
        try:
            search_value = str(args.single_contain_string).encode("utf-8")
            assert search_value is not None
            search_values.append(search_value)
        except Exception as e:
            abort("errors with --single-contain-string options", e)
    elif args.single_contain_hex:
        try:
            search_value = bytes.fromhex(args.single_contain_hex)
            assert search_value is not None
            search_values.append(search_value)
        except Exception as e:
            abort("errors with --single-contain-hex options", e)

    single_payload: bytes | None = None
    if args.single_payload:
        single_payload = decode_base64_string(args.single_payload)
    elif args.single_payload_hex:
        try:
            single_payload: bytes = bytes.fromhex(args.single_payload_hex)
        except BaseException:
            pass
    elif args.single_payload_pickle_hex:
        try:
            single_payload: bytes = bytes.fromhex(args.single_payload_pickle_hex)
        except:
            pass
    if single_payload:
        payloads.append(single_payload)

    cookies = None
    if not args.full_cookies:
        if args.full_cookies_hex:
            try:
                _cookies_hex: bytes = bytes.fromhex(args.full_cookies_hex)
                _cookies_string: str = _cookies_hex.decode("utf-8")
                cookies = orjson_loads(_cookies_string)
            except Exception as e:
                print(f"errors with full cookies from hex. {e}, cookies set to None")
    else:
        try:
            cookies = orjson_loads(args.full_cookies)
        except Exception as e:
            print(
                f"errors with full cookies from string(json). {e}, cookies set to None"
            )

    if not args.full_headers:
        if args.full_headers_hex:
            try:
                _headers_hex: bytes = bytes.fromhex(args.full_headers_hex)
                _headers_string: str = _headers_hex.decode("utf-8")
                headers = orjson_loads(_headers_string)
            except Exception as e:
                print(f"errors with full headers from hex. {e}, headers set to None")
                headers = {}
        elif args.user_agent.lower() == "no":
            headers = {}
        elif args.user_agent == "random":
            headers = {"User-Agent": return_user_agent()}
        else:
            headers = {"User-Agent": args.user_agent}
    else:
        try:
            headers = orjson_loads(args.full_headers)
        except Exception as e:
            print(f"errors with full headers. {e}, headers set to None")
            headers = {}

    if args.ssl_check:
        scheme = "https"
    else:
        scheme = "http"

    try:
        dns_values = args.dns_servers
        dns_ipv4 = []
        for value in dns_values.split(","):
            if is_ip(value.strip()):
                dns_ipv4.append(value.strip())
    except Exception as exp:
        print(f"errors with --dns-servers, set defaults: {DEFAULT_NAME_SERVERS}")
        dns_ipv4 = DEFAULT_NAME_SERVERS.split(",")

    target_settings = TargetConfig(
        **{
            "port": args.port,
            "ssl_check": args.ssl_check,
            "total_timeout": args.total_timeout,
            "list_payloads": payloads,
            "search_values": search_values,
            "max_size": args.max_size,
            "python_payloads": args.python_payloads,
            "generator_payloads": args.generator_payloads,
            "headers": headers,
            "cookies": cookies,
            "scheme": scheme,
            "endpoint": args.endpoint,
            "method": args.method,
            "hostname": "",
            "single_payload_type": args.single_payload_type,
            "allow_redirects": args.allow_redirects,
        }
    )

    app_settings = AppConfig(
        **{
            "senders": args.senders,
            "queue_sleep": args.queue_sleep,
            "statistics": args.show_statistics,
            "dns_servers": dns_ipv4,
            "total_timeout": args.total_timeout,
            "input_file": input_file,
            "input_stdin": args.input_stdin,
            "single_targets": args.single_targets,
            "output_file": output_file,
            "write_mode": write_mode,
            "show_only_success": args.show_only_success,
            "endpoint": args.endpoint,
            "status_code": args.status_code,
            "without_base64": args.without_base64,
            "without_hashs": args.without_hashs,
            "without_certraw": args.without_certraw,
            "proxy_connections": proxy_connections,
            "custom_module": args.custom_module,
            "url_custom_module": args.url_custom_module,
        }
    )
    return target_settings, app_settings


def abort(message: str, exc: Exception = None, exit_code: int = 1):
    print(message, file=stderr)
    if exc:
        print(exc, file=stderr)
    exit(exit_code)


def parse_settings_file(file_path: str) -> Tuple[TargetConfig, AppConfig]:
    raise NotImplementedError("config read")


def check_prefix_directory(
    prefix_hash: str, path_directory_modules: "Path"
) -> Tuple[bool, str]:
    try:
        if path_directory_modules.is_dir():
            if not (path_directory_modules / "__init__.py").exists():
                (path_directory_modules / "__init__.py").touch()
            all_directory_data = path_directory_modules.glob(
                f"{prefix_hash}*/{prefix_hash}*"
            )
            for record in all_directory_data:
                if record.is_file():
                    if record.stat().st_size > 0:
                        return True, record.stem
        return False, ""
    except Exception as exp:
        return False, str(exp)


async def download_module(
    url_auth: Optional[Tuple], proj_root: "Path", directory_modules: str
) -> Optional[str]:
    url, auth = url_auth
    basic_auth = BasicAuth(auth) if auth else None
    status = False
    filename_module_prefix = haslib_md5(url.encode()).hexdigest()
    path_directory_modules = proj_root / "lib" / directory_modules
    status_exists_custom_module, name_module = check_prefix_directory(
        filename_module_prefix, path_directory_modules
    )
    if status_exists_custom_module:
        return name_module
    else:
        if name_module:
            print(f"errors: {name_module}")
        try:
            async with aiohttp_ClientSession(auth=basic_auth) as client:
                async with client.get(url, ssl=False, timeout=30) as response:
                    if response.status == 200:
                        data = await response.read()
                        filename_module_suffix = haslib_md5(data).hexdigest()
                        filename_module = (
                            f"{filename_module_prefix}_{filename_module_suffix}"
                        )
                        async with aiofiles_open(
                            f"/tmp/{filename_module}", "wb"
                        ) as file_tmp:
                            await file_tmp.write(data)
            file_downloaded = Path(f"/tmp/{filename_module}")
            if file_downloaded.stat().st_size > 0:
                status = True
        except Exception as e:
            print(f"exit, error: {e}")
            exit(1)
        else:
            if status:
                try:
                    ready_module = (
                        proj_root / "lib" / directory_modules / filename_module
                    )
                    if not ready_module.exists():
                        ready_module.mkdir(exist_ok=True)
                    shutil_copy(file_downloaded, ready_module / f"{filename_module}.py")
                    _init = ready_module / "__init__.py"
                    _init.touch()
                    return str(filename_module)
                except Exception as e:
                    print(f"exit, error: {e}")
                    exit(1)


def load_custom_worker(config_custom_module, directory_modules):
    try:
        module_name = (
            f"lib.{directory_modules}.{config_custom_module}.{config_custom_module}"
        )
        _mod = importlib.import_module(module_name)
        custom_worker = getattr(_mod, NAME_CUSTOM_WORKER_CLASS)
        return custom_worker
    except Exception as e:
        print(f"exit, error: {e}")
        exit(1)


def check_config_url(url_module: str) -> Optional[Tuple[str, Tuple[str, str]]]:
    try:
        url_module_value = urlparse(url_module)
        basic_auth = (url_module_value.username, url_module_value.password)
        url = f"{url_module_value.scheme}:{url_module_value.path}"
        if not all(basic_auth):
            basic_auth = None
        if url:
            return url, basic_auth
    except Exception as e:
        print(f"exit, error: {e}")
        exit(1)


def return_user_agent() -> str:
    """
    функция возвращается строку с user-agent
    :return:
    """
    user_agents = [
        "Mozilla/5.0(Windows NT 10.0;Win64;x64;rv: 59.0) Gecko / 20100101 Firefox / 59.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36.",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/43.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/41.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2704.103 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 OPR/42.0.2393.94",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 OPR/42.0.2393.94",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36 OPR/47.0.2631.39",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52",
        "Mozilla/5.0 (Windows NT 5.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36 OPR/47.0.2631.39",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36 OPR/52.0.2871.99",
        "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991",
        "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991",
        "Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991",
        "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 OPR/42.0.2393.94",
        "Mozilla/5.0 (Windows NT 5.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 OPR/42.0.2393.94",
        "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 OPR/42.0.2393.94",
        "Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 OPR/42.0.2393.94",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36 OPR/52.0.2871.99",
        "Mozilla/5.0 (Windows NT 6.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36 OPR/47.0.2631.39",
        "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52",
        "Mozilla/5.0 (Windows NT 6.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52",
        "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52",
        "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36 OPR/47.0.2631.39",
        "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36 OPR/47.0.2631.39",
        "Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36 OPR/47.0.2631.39",
        "Mozilla/5.0 (Linux; Android; 4.1.2; GT-I9100 Build/000000) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/25.0.1234.12 Mobile Safari/537.22 OPR/14.0.123.123",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36 OPR/46.0.2597.57",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36 OPR/52.0.2871.99",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 OPR/32.0.1948.25",
        "Opera/9.80 (X11; Linux zvav; U; en) Presto/2.12.423 Version/12.16",
        "Mozilla/5.0 (Windows NT 6.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36 OPR/52.0.2871.99",
        "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36 OPR/52.0.2871.99",
        "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36 OPR/52.0.2871.99",
        "Mozilla/5.0 (Windows NT 5.1; U; en) Opera 8.01",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36 OPR/36.0.2130.80",
        "Mozilla/4.0 (compatible; MSIE 6.0; MSIE 5.5; Windows NT 5.0) Opera 7.02 Bork-edition [en]",
        "Opera/9.80 (Macintosh; Intel Mac OS X 10.10.5) Presto/2.12.388 Version/12.16",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36 OPR/26.0.1656.60",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36 OPR/46.0.2597.57",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.50",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.1144",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36 OPR/26.0.1656.60",
        "Opera/9.80 (X11; Linux zvav; U; en) Presto/2.8.119 Version/11.10",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41",
        "Mozilla/5.0 (Linux; U; Android 5.0.2; zh-CN; Redmi Note 3 Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 OPR/11.2.3.102637 Mobile Safari/537.36",
        "Opera/9.80 (Windows NT 6.2; Win64; x64) Presto/2.12.388 Version/12.15",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.2743.82 Safari/537.36 OPR/39.0.2256.43",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36 OPR/52.0.2871.64",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
        "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 4.4.2; XMP-6250 Build/HAWK) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Safari/537.36 ADAPI/2.0 (UUID:9e7df0ed-2a5c-4a19-bec7-2cc54800f99d) RK3188-ADAPI/1.2.84.533 (MODEL:XMP-6250)",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 6.0.1; SM-G532G Build/MMB29T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.83 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.109 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 6.0; vivo 1713 Build/MRA58K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.124 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.63 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 7.1; Mi A1 Build/N2G47H) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.83 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.65 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
        "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 6.0.1; CPH1607 Build/MMB29M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/63.0.3239.111 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 5.1; A37f Build/LMY47V) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.93 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 6.0.1; vivo 1603 Build/MMB29M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.83 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 6.0.1; Redmi 4A Build/MMB29M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.116 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.104 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 6.0; vivo 1606 Build/MMB29M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.124 Mobile Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Mwendo/1.1.5 Safari/537.21",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.7 (KHTML, like Gecko) Version/9.1.2 Safari/601.7.7",
        "Mozilla/5.0 (iPad; CPU OS 9_3_2 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13F69 Safari/601.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B143 Safari/601.1",
        "Mozilla/5.0 (iPad; CPU OS 9_3_5 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13G36 Safari/601.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8",
        "Mozilla/5.0 (iPad; CPU OS 10_2_1 like Mac OS X) AppleWebKit/602.4.6 (KHTML, like Gecko) Version/10.0 Mobile/14D27 Safari/602.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 10_2_1 like Mac OS X) AppleWebKit/602.4.6 (KHTML, like Gecko) Version/10.0 Mobile/14D27 Safari/602.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/604.5.6 (KHTML, like Gecko) Version/11.0.3 Safari/604.5.6",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/603.2.4 (KHTML, like Gecko) Version/10.1.1 Safari/603.2.4",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/601.4.4 (KHTML, like Gecko) Version/9.0.3 Safari/601.4.4",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/603.1.30 (KHTML, like Gecko) Version/10.1 Safari/603.1.30",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/602.4.8 (KHTML, like Gecko) Version/10.0.3 Safari/602.4.8",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/601.5.17 (KHTML, like Gecko) Version/9.1 Safari/601.5.17",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 9_3 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13E188a Safari/601.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/601.6.17 (KHTML, like Gecko) Version/9.1.1 Safari/601.6.17",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.0 Mobile/14G60 Safari/602.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0.2 Safari/604.4.7",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 8_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B410 Safari/600.1.4",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 11_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 9_3_2 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13F69 Safari/601.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Safari/604.1.38",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/601.2.7 (KHTML, like Gecko) Version/9.0.1 Safari/601.2.7",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 10_2 like Mac OS X) AppleWebKit/602.3.12 (KHTML, like Gecko) Version/10.0 Mobile/14C92 Safari/602.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/601.7.8 (KHTML, like Gecko) Version/9.1.3 Safari/537.86.7",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0.1 Safari/604.3.5",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 9_3_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13E238 Safari/601.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_2) AppleWebKit/602.3.12 (KHTML, like Gecko) Version/10.0.2 Safari/602.3.12",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 9_2_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13D15 Safari/601.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/534.59.10 (KHTML, like Gecko) Version/5.1.9 Safari/534.59.10",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.78.2 (KHTML, like Gecko) Version/6.1.6 Safari/537.78.2",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/601.4.4 (KHTML, like Gecko) Version/9.0.3 Safari/601.4.4",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 10_1_1 like Mac OS X) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0 Mobile/14B100 Safari/602.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/601.5.17 (KHTML, like Gecko) Version/9.1 Safari/601.5.17",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 11_2_1 like Mac OS X) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0 Mobile/15C153 Safari/604.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.8 (KHTML, like Gecko) Version/9.1.3 Safari/601.7.8",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_2 like Mac OS X) AppleWebKit/603.2.4 (KHTML, like Gecko) Version/10.0 Mobile/14F89 Safari/602.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/14A456 Safari/602.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 11_2_6 like Mac OS X) AppleWebKit/604.5.6 (KHTML, like Gecko) Version/11.0 Mobile/15D100 Safari/604.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
    ]
    return choice(user_agents)
