import abc
import asyncio
from abc import ABC
from asyncio import Queue
from base64 import b64encode
from datetime import datetime
from hashlib import sha256, sha1, md5
from ipaddress import IPv4Address
from os import environ
# noinspection PyUnresolvedReferences,PyProtectedMember
from ssl import _create_unverified_context as ssl_create_unverified_context
from typing import Optional, Callable, Any, Coroutine, List
from aiohttp import ClientSession, ClientTimeout, TCPConnector, ClientResponse, TraceConfig, AsyncResolver
from aioconsole import ainput
from aiofiles import open as aiofiles_open
from ujson import dumps as ujson_dumps
from lib.core import create_template_struct, convert_bytes_to_cert, create_error_template, Stats, AppConfig, \
    Target, TargetConfig, CONST_ANY_STATUS
from lib.util import access_dot_path, is_ip, filter_bytes, write_to_file, write_to_stdout, read_http_content
from .factories import create_targets_http_protocol

__all__ = ['QueueWorker', 'TargetReader', 'TargetFileReader', 'TargetStdinReader', 'TaskProducer',
           'Executor', 'OutputPrinter', 'TargetWorker', 'create_io_reader', 'get_async_writer',
           'on_request_start', 'on_request_end', 'WrappedResponseClass', 'return_ip_from_deep']

STOP_SIGNAL = b'check for end'


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


class WrappedResponseClass(ClientResponse):

    def __init__(self, *args, **kwargs):
        super(WrappedResponseClass, self).__init__(*args, **kwargs)
        self._peer_cert = None
        self._ssl_prot = None
        self._ssl_prot_extra = None

    async def start(self, connection, read_until_eof=False):
        try:
            self._ssl_prot = connection.transport.get_extra_info('ssl_object')
            self._peer_cert = self._ssl_prot.getpeercert(binary_form=True)
        except Exception as e:
            pass
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


class QueueWorker(metaclass=abc.ABCMeta):
    def __init__(self, stats: Optional[Stats] = None):
        self.stats = stats

    @abc.abstractmethod
    async def run(self):
        pass


class InputProducer:
    """
    Produces raw messages for workers
    """

    def __init__(self, stats: Stats, input_queue: Queue, target_conf: TargetConfig, send_limit: int, queue_sleep: int):
        self.stats = stats
        self.input_queue = input_queue
        self.target_conf = target_conf
        self.send_limit = send_limit
        self.queue_sleep = queue_sleep

    async def send(self, linein):
        if linein:
            targets = create_targets_http_protocol(linein, self.target_conf)  # generator
            if targets:
                for target in targets:
                    check_queue = True
                    while check_queue:
                        size_queue = self.input_queue.qsize()
                        if size_queue < self.send_limit:
                            if self.stats:
                                self.stats.count_input += 1
                            self.input_queue.put_nowait(target)
                            check_queue = False
                        else:
                            await asyncio.sleep(self.queue_sleep)

    async def send_stop(self):
        await self.input_queue.put(STOP_SIGNAL)


class TargetReader(QueueWorker, ABC):
    """
    Reads raw input messages from any source ans sends them to workers via producer
    """

    def __init__(self, stats: Stats, input_queue: Queue, producer: InputProducer):
        super().__init__(stats)
        self.input_queue = input_queue
        self.producer = producer


class TargetFileReader(TargetReader):
    """
    Reads raw input messages from text file
    """

    def __init__(self, stats: Stats, input_queue: Queue, producer: InputProducer, file_path: str):
        super().__init__(stats, input_queue, producer)
        self.file_path = file_path

    async def run(self):
        async with aiofiles_open(self.file_path, mode='rt') as f:
            async for line in f:
                linein = line.strip()
                if linein:
                    await self.producer.send(linein)

        await self.producer.send_stop()


class TargetSingleReader(TargetReader):
    """
    Reads --target input messages from args
    """

    def __init__(self, stats: Stats, input_queue: Queue, producer: InputProducer, single_targets: str):
        super().__init__(stats, input_queue, producer)
        self.single_targets = single_targets

    async def run(self):
        for single_target in self.single_targets:
            linein = single_target.strip()
            if linein:
                await self.producer.send(linein)
        await self.producer.send_stop()


class TargetStdinReader(TargetReader):
    """
    Reads raw input messages from STDIN
    """

    async def run(self):
        """
        посредством модуля aioconsole функция "асинхронно" читает из stdin записи, представляющие собой
        обязательно или ip адрес или запись подсети в ipv4
        из данной записи формируется экзэмпляр Target, который отправляется в Очередь
        TODO: использовать один модуль - или aioconsole или aiofiles
        """
        while True:
            try:
                linein = (await ainput()).strip()
                await self.producer.send(linein)
            except EOFError:
                await self.producer.send_stop()
                break


class TaskProducer(QueueWorker):
    """
    Creates tasks for tasks queue
    """

    def __init__(self, stats: Stats, in_queue: Queue, tasks_queue: Queue, worker: 'TargetWorker'):
        super().__init__(stats)
        self.in_queue = in_queue
        self.tasks_queue = tasks_queue
        self.worker = worker

    async def run(self):
        while True:
            # wait for an item from the "start_application"
            target = await self.in_queue.get()
            if target == STOP_SIGNAL:
                await self.tasks_queue.put(STOP_SIGNAL)
                break
            if target:
                coro = self.worker.do(target)
                task = asyncio.create_task(coro)
                await self.tasks_queue.put(task)


class Executor(QueueWorker):
    """
    Gets tasks from tasks queue and launch execution for each of them
    """

    def __init__(self, stats: Stats, tasks_queue: Queue, out_queue: Queue):
        super().__init__(stats)
        self.tasks_queue = tasks_queue
        self.out_queue = out_queue

    async def run(self):
        while True:
            # wait for an item from the "start_application"
            task = await self.tasks_queue.get()
            if task == STOP_SIGNAL:
                await self.out_queue.put(STOP_SIGNAL)
                break
            if task:
                await task


class OutputPrinter(QueueWorker):
    """
    Takes results from results queue and put them to output
    """

    def __init__(self, output_file: str, stats: Stats, in_queue: Queue, io, async_writer) -> None:
        super().__init__(stats)
        self.in_queue = in_queue
        self.async_writer = async_writer
        self.io = io
        self.output_file = output_file

    async def run(self):
        while True:
            line = await self.in_queue.get()
            if line == STOP_SIGNAL:
                break
            if line:
                await self.async_writer(self.io, line)

        await asyncio.sleep(0.5)
        if self.stats:
            statistics = self.stats.dict()
            if self.output_file == '/dev/stdout':
                await self.io.write(ujson_dumps(statistics).encode('utf-8') + b'\n')
            else:
                # dirty temp hack
                if not environ.get('CLOUD'):
                    async with aiofiles_open('/dev/stdout', mode='wb') as stats:
                        await stats.write(ujson_dumps(statistics).encode('utf-8') + b'\n')
                else:
                    print(ujson_dumps(statistics), flush=True)


async def on_request_start(session, trace_config_ctx, params):
    trace_config_ctx.start = asyncio.get_event_loop().time()


async def on_request_end(session, trace_config_ctx, params):
    elapsed = asyncio.get_event_loop().time() - trace_config_ctx.start
    if trace_config_ctx.trace_request_ctx:
        trace_config_ctx.trace_request_ctx['duration'] = round(elapsed, 4)


class TargetWorker:
    """
    Runs payload against target
    """

    def __init__(self, stats: Stats, semaphore: asyncio.Semaphore, output_queue: asyncio.Queue, app_config: AppConfig):
        self.stats = stats
        self.semaphore = semaphore
        self.output_queue = output_queue
        self.app_config = app_config
        self.success_only = app_config.show_only_success
        self.trace_request_ctx = {'request': True}

    # noinspection PyBroadException
    async def do(self, target: Target):
        """
        сопрограмма, осуществляет подключение к Target, отправку и прием данных, формирует результата в виде dict
        """

        def update_line(json_record, target):
            try:
                json_record['ip'] = target.ip
                json_record['meta'] = {}
                try:
                    json_record['meta']['ipv4'] = int(IPv4Address(target.ip))
                except:
                    pass
                try:
                    json_record['meta']['datetime'] = int(datetime.now().timestamp())
                except:
                    pass
                try:
                    json_record['meta']['port'] = int(target.port)
                except:
                    pass
            except:
                pass
            return json_record

        async with self.semaphore:
            result = None
            timeout = ClientTimeout(total=target.total_timeout)

            # region tmp disable
            trace_config = TraceConfig()
            trace_config.on_request_start.append(on_request_start)
            trace_config.on_request_end.append(on_request_end)
            # endregion
            nameservers: List[str] = self.app_config.dns_servers
            resolver = AsyncResolver(nameservers=nameservers)
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
            try:
                async with session.request(target.method,
                                           target.url,
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
                    # endregion
                    if target.method in ['GET', 'POST', 'PUT', 'DELETE', 'UPDATE']:
                        buffer = b""
                        try:
                            read_c = asyncio.wait_for(read_http_content(response, n=target.max_size),
                                                      timeout=target.total_timeout)
                            buffer = await read_c
                        except Exception as e:
                            pass
                        else:
                            if filter_bytes(buffer, target):
                                _default_record['data']['http']['result']['response']['content_length'] = len(buffer)
                                _default_record['data']['http']['result']['response']['body'] = ''
                                try:
                                    _default_record['data']['http']['result']['response']['body'] = buffer.decode()
                                except Exception as e:
                                    pass
                                if not self.app_config.without_base64:
                                    try:
                                        _base64_data = b64encode(buffer).decode('utf-8')
                                        _default_record['data']['http']['result']['response']['body_raw'] = _base64_data
                                    except Exception as e:
                                        pass
                                if not self.app_config.without_hashs:
                                    try:
                                        hashs = {'sha256': sha256,
                                                 'sha1': sha1,
                                                 'md5': md5}
                                        for namehash, func in hashs.items():
                                            hm = func()
                                            hm.update(buffer)
                                            _default_record['data']['http']['result']['response'][f'body_{namehash}'] = hm.hexdigest()
                                    except Exception as e:
                                        pass
                                result = update_line(_default_record, target)
                            else:
                                # TODO: добавить статус success-not-contain для обозначения того,
                                #  что сервис найден, но не попал под фильтр?
                                result = create_error_template(target, error_str='', status_string='success-not-contain')
                    if result:
                        if not result['ip']:
                            result['ip']: str = return_ip_from_deep(session, response)
                            if result['ip']:
                                if result.get('meta'):
                                    try:
                                        result['meta']['ipv4'] = int(IPv4Address(result['ip']))
                                    except:
                                        pass
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
                if not (self.app_config.status_code == CONST_ANY_STATUS):
                    response_status = access_dot_path(result, 'data.http.result.response.status_code')
                    if response_status:
                        if self.app_config.status_code != response_status:
                            error_str = f'status code: {response_status} is not equal to filter: {self.app_config.status_code}'
                            result = create_error_template(target, error_str=error_str, status_string='success-not-need-status')
                            if self.stats:
                                self.stats.count_good -= 1
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


def create_io_reader(stats: Stats, queue_input: Queue, target: TargetConfig, app_config: AppConfig) -> TargetReader:
    message_producer = InputProducer(stats, queue_input, target, app_config.senders - 1, app_config.queue_sleep)
    if app_config.input_stdin:
        return TargetStdinReader(stats, queue_input, message_producer)
    if app_config.single_targets:
        return TargetSingleReader(stats, queue_input, message_producer, app_config.single_targets)
    elif app_config.input_file:
        return TargetFileReader(stats, queue_input, message_producer, app_config.input_file)
    else:
        # TODO : rethink...
        print("""errors, set input source:
         --stdin read targets from stdin;
         -t,--targets set targets, see -h;
         -f,--input-file read from file with targets, see -h""")
        exit(1)


def get_async_writer(app_settings: AppConfig) -> Callable[[Any, str], Coroutine]:
    if app_settings.write_mode == 'a':
        return write_to_file
    return write_to_stdout
