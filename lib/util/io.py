import asyncio
from base64 import b64decode
from typing import Any, Tuple
from aiohttp import ClientConnectionError, ClientResponse
from lib.core import create_error_template, Target
from collections.abc import Mapping
from urllib3.fields import RequestField
from urllib3.filepost import encode_multipart_formdata
from os.path import basename as  os_path_basename
__all__ = ['single_read', 'multi_read', 'write_to_stdout', 'write_to_file', 'decode_base64_string',
           'filter_bytes', 'read_http_content', 'encode_files_payload']

basestring = (str, bytes)

async def single_read(reader: asyncio.StreamReader, target: Target) -> Tuple[bool, Any]:
    # region old
    future_reader = reader.read(target.max_size)
    try:
        # через asyncio.wait_for - задаем время на чтение из
        # соединения
        data = await asyncio.wait_for(future_reader, timeout=target.read_timeout)
        return True, data
    except Exception as e:
        result = create_error_template(target, str(e))
        return False, result


# noinspection PyBroadException
async def multi_read(reader: asyncio.StreamReader, target: Target) -> Tuple[bool, Any]:
    count_size = target.max_size
    try:
        data = b''
        while True:
            try:
                future_reader = reader.read(count_size)
                _data = await asyncio.wait_for(future_reader, timeout=0.5)
                if _data:
                    data += _data
                    count_size = count_size - len(data)
                else:
                    break
                if count_size <= 0:
                    break
            except Exception:
                break

        if len(data) == 0:
            return False, create_error_template(target, 'empty')
        else:
            return True, data
    except Exception as e:
        return False, create_error_template(target, str(e))


async def read_http_content(self: ClientResponse, n: int = -1) -> bytes:
    """
    # https://github.com/aio-libs/aiohttp/issues/2638
    Read up to 'n' bytes of the response payload.
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

            try:
                for trace in self._traces:
                    await trace.send_response_chunk_received(method=self.method,
                                                             url=self.url,
                                                             chunk=self._body)
            except:
                pass

        except BaseException:
            self.close()
            raise
    elif self._released:
        raise ClientConnectionError('Connection closed')
    return self._body




async def write_to_stdout(io, record: str):
    """
    Write in 'wb' mode to io, input string in utf-8
    """
    return await io.write(record.encode('utf-8') + b'\n')


async def write_to_file(io, record: str):
    """
    Write in 'text' mode to io
    """
    return await io.write(record + '\n')


# noinspection PyBroadException
def decode_base64_string(string: str, encoding='utf-8') -> bytes:
    """
    Tries to decode base64 string
    """
    try:
        return b64decode(string.encode(encoding))
    except Exception:
        pass


def filter_bytes(buffer: bytes, target: Target) -> bool:
    """
    Checks given bytes for matches across target's search_values field.
    Returns True if there are not search_values
    """
    return not target.search_values or any(x in buffer for x in target.search_values)


# region functions from requests module
def to_key_val_list(value):
    """Take an object and test to see if it can be represented as a
    dictionary. If it can be, return a list of tuples, e.g.,

    ::

        >>> to_key_val_list([('key', 'val')])
        [('key', 'val')]
        >>> to_key_val_list({'key': 'val'})
        [('key', 'val')]
        >>> to_key_val_list('string')
        Traceback (most recent call last):
        ...
        ValueError: cannot encode objects that are not 2-tuples

    :rtype: list
    """
    if value is None:
        return None

    if isinstance(value, (str, bytes, bool, int)):
        raise ValueError('cannot encode objects that are not 2-tuples')

    if isinstance(value, Mapping):
        value = value.items()

    return list(value)


def guess_filename(obj):
    """Tries to guess the filename of the given object."""

    name = getattr(obj, 'name', None)
    if (name and isinstance(name, basestring) and name[0] != '<' and
            name[-1] != '>'):
        return os_path_basename(name)


def encode_files_payload(files, data, headers):
    """Build the body for a multipart/form-data request.

    Will successfully encode files when passed as a dict or a list of
    tuples. Order is retained if data is a list of tuples but arbitrary
    if parameters are supplied as a dict.
    The tuples may be 2-tuples (filename, fileobj), 3-tuples (filename, fileobj, contentype)
    or 4-tuples (filename, fileobj, contentype, custom_headers).
    """
    if (not files):
        raise ValueError("Files must be provided.")
    elif isinstance(data, basestring):
        raise ValueError("Data must not be a string.")

    new_fields = []
    fields = to_key_val_list(data or {})
    files = to_key_val_list(files or {})

    for field, val in fields:
        if isinstance(val, basestring) or not hasattr(val, '__iter__'):
            val = [val]
        for v in val:
            if v is not None:
                # Don't call str() on bytestrings: in Py3 it all goes wrong.
                if not isinstance(v, bytes):
                    v = str(v)

                new_fields.append(
                    (field.decode('utf-8') if isinstance(field, bytes) else field,
                     v.encode('utf-8') if isinstance(v, str) else v))

    for (k, v) in files:
        # support for explicit filename
        ft = None
        fh = None
        if isinstance(v, (tuple, list)):
            if len(v) == 2:
                fn, fp = v
            elif len(v) == 3:
                fn, fp, ft = v
            else:
                fn, fp, ft, fh = v
        else:
            fn = guess_filename(v) or k
            fp = v

        if isinstance(fp, (str, bytes, bytearray)):
            fdata = fp
        elif hasattr(fp, 'read'):
            fdata = fp.read()
        elif fp is None:
            continue
        else:
            fdata = fp

        rf = RequestField(name=k, data=fdata, filename=fn, headers=fh)
        rf.make_multipart(content_type=ft)
        new_fields.append(rf)
    body, content_type = encode_multipart_formdata(new_fields)
    headers['Content-Type'] = content_type
    return body, headers
# endregion functions from requests module
