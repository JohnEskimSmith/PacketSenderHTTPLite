import abc
import asyncio
from abc import ABC
from asyncio import Queue
from base64 import b64encode
from hashlib import sha256, sha1, md5
from hexdump import hexdump
# noinspection PyUnresolvedReferences,PyProtectedMember
from ssl import _create_unverified_context as ssl_create_unverified_context
from typing import Optional, Callable, Any, Coroutine
from aiohttp import ClientSession, ClientTimeout, TCPConnector, ClientResponse, TraceConfig
from aioconsole import ainput
from aiofiles import open as aiofiles_open
from ujson import dumps as ujson_dumps

from lib.core import create_template_struct, convert_bytes_to_cert, create_error_template, Stats, AppConfig, \
    Target, TargetConfig, CONST_ANY_STATUS
from lib.util import access_dot_path, is_ip, is_network, single_read, multi_read, \
    filter_bytes, write_to_file, write_to_stdout, read_http_content
from .factories import create_targets_http_protocol

__all__ = ['QueueWorker', 'TargetReader', 'TargetFileReader', 'TargetStdinReader', 'TaskProducer', 'Executor',
           'OutputPrinter', 'TargetWorker', 'create_io_reader', 'get_async_writer']

STOP_SIGNAL = b'check for end'


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
                async with aiofiles_open('/dev/stdout', mode='wb') as stats:
                    await stats.write(ujson_dumps(statistics).encode('utf-8') + b'\n')


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

    # noinspection PyBroadException
    async def do(self, target: Target):
        """
        сопрограмма, осуществляет подключение к Target, отправку и прием данных, формирует результата в виде dict
        """

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
            trace_config = TraceConfig()
            trace_config.on_request_start.append(on_request_start)
            trace_config.on_request_end.append(on_request_end)

            if target.ssl_check:
                conn = TCPConnector(ssl=False, limit_per_host=0)
                session = ClientSession(
                    timeout=timeout,
                    connector=conn,
                    response_class=WrappedResponseClass,
                    trace_configs=[trace_config])
            else:
                session = ClientSession(timeout=timeout, trace_configs=[trace_config])
            try:
                trace_request_ctx = {'request': True}
                async with session.request(target.method,
                                           target.url,
                                           timeout=timeout,
                                           headers=target.headers,
                                           allow_redirects=target.allow_redirects,
                                           data=target.payload,
                                           trace_request_ctx=trace_request_ctx) as response:
                    if not (self.app_config.status_code == CONST_ANY_STATUS):
                        if self.app_config.status_code != response.status:
                            _response_status = response.status
                            await asyncio.sleep(0.005)
                            try:
                                await session.close()
                            except:
                                pass
                            raise ValueError(f'status code: {_response_status} is not equal to filter: {self.app_config.status_code}')

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
                            buffer = await read_http_content(response, n=target.max_size)
                        except Exception as e:
                            pass
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
                        try:
                            hashs = {'sha256': sha256,
                                     'sha1': sha1,
                                     'md5': md5}
                            for namehash, func in hashs.items():
                                hm = func()
                                hm.update(buffer)
                                _default_record['data']['http']['result']['response'][f'body_{namehash}'] = hm.hexdigest(
                                )
                        except Exception as e:
                            pass
                        if not self.app_config.without_hexdump:
                            _default_record['data']['http']['result']['response']['body_hexdump'] = ''
                            try:
                                hdump = hexdump(buffer, result='return')
                                _output = b64encode(bytes(hdump, 'utf-8'))
                                output = _output.decode('utf-8')
                                _default_record['data']['http']['result']['response']['body_hexdump'] = output
                            except Exception as e:
                                pass

                    result = update_line(_default_record, target)
                    if result:
                        if len(result['ip']) == 0:
                            _ip = return_ip_from_deep(session, response)
                            result['ip'] = _ip
                await asyncio.sleep(0.005)
                try:
                    await session.close()
                except:
                    pass
            except Exception as exp:
                result = create_error_template(target, str(exp))
                await asyncio.sleep(0.005)
                try:
                    await session.close()
                except:
                    pass
                try:
                    await conn.close()
                except:
                    pass
            if result:
                if 'duration' in trace_request_ctx:
                    request_duration = trace_request_ctx['duration']
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
