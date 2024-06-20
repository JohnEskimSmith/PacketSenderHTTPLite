from base64 import b64decode
from contextlib import AsyncExitStack
from os import environ as os_environ
from sys import stderr
from tempfile import NamedTemporaryFile
from typing import Dict, List, Optional, Tuple
from uuid import uuid4

import msgpack
from aiobotocore.session import AioSession

from lib.util import access_dot_path

__all__ = ["parse_args_from_sqs_message", "parse_cloud_env"]

CONST_SPECIAL_PREFIX_BUCKET = "destination_"


def abort(message: str, exc: Exception = None, exit_code: int = 1):
    print(message, file=stderr)
    if exc:
        print(exc, file=stderr)
    exit(exit_code)


CONST_IO_FIELDS = ("input-file", "output-file")


def parse_sqs_message_yandex_msgpack(
    event: Dict,
) -> Optional[Tuple[Optional[Dict], str, str]]:
    try:
        body_current_message = access_dot_path(
            event["messages"][0], "details.message.body"
        )
        message_value: Dict = msgpack.unpackb(b64decode(body_current_message.encode()))
        if payload := message_value.get("payload"):
            if type_payload := payload.get("type"):
                if type_payload == "strings":
                    if data := payload.get("data"):
                        tmp_file = NamedTemporaryFile(delete=False, mode="wt")
                        tmp_file.write("\n".join(data) + "\n")
                        tmp_file.close()
                        return (
                            message_value.get("settings"),
                            type_payload,
                            tmp_file.name,
                        )
            else:
                pass
                # TODO rethink
    except Exception as exp:
        print(exp)


async def create_aws_client(
    session: AioSession, exit_stack: AsyncExitStack, auth_struct: Dict
):
    # Create client and add cleanup
    client = await exit_stack.enter_async_context(session.create_client(**auth_struct))
    return client


def create_default_info_for_routes_bucket(settings_s3: Dict) -> Dict:
    endpoint = settings_s3["endpoint"].strip("/")
    dest, database, space = endpoint.split("/")
    try:
        _name_task = settings_s3["name"]
    except:
        _name_task = space
    currentuuid = uuid4().hex
    s3_prefix_key = f"{database}/{space}/{_name_task}_uuid_{currentuuid}.njson"
    return {"bucket": CONST_SPECIAL_PREFIX_BUCKET + dest, "key": s3_prefix_key}


def create_args_list(settings: Dict, files: Tuple[str, str]) -> List[str]:
    arguments_from_string = []
    for k, v in settings.items():
        if isinstance(v, bool):
            arguments_from_string.append(f"--{k}")
        else:
            arguments_from_string.append(f"--{k}={v}")
    arguments_from_string.append(f"--{CONST_IO_FIELDS[0]}={files[0]}")
    arguments_from_string.append(f"--{CONST_IO_FIELDS[1]}={files[1]}")
    return arguments_from_string


def parse_args_from_sqs_message(event: Dict) -> Optional[List[str]]:
    struct_from_message: Optional[Tuple[Optional[Dict], str, str]] = (
        parse_sqs_message_yandex_msgpack(event)
    )
    if struct_from_message:
        raw_settings, type_payload, input_file = struct_from_message
        output_file = f"/tmp/{uuid4().hex}.results"
        if not input_file:
            abort(f"ERROR: errors when creating input file(temp.)")
        if not raw_settings:
            abort(f"ERROR: errors when decode settings")
        args_list: List[str] = create_args_list(raw_settings, (input_file, output_file))
        return args_list
    else:
        abort(f"ERROR: errors when decode message from SQS")


async def parse_cloud_env(
    file_with_result: str, s3_endpoint: str = "/mongo/http/cloud"
) -> Tuple[Dict, Optional[Dict]]:
    # region client s3
    s3_out_struct = {
        "service_name": "s3",
        "region_name": os_environ.get("region_name", "ru-east-1"),
        "use_ssl": True,
        "endpoint_url": os_environ["endpoint_url"],
        "aws_secret_access_key": os_environ["aws_secret_access_key"],
        "aws_access_key_id": os_environ["aws_access_key_id"],
        "endpoint": s3_endpoint,
        "name": os_environ.get("name_task", "simple"),
    }

    keys = [
        "service_name",
        "endpoint_url",
        "region_name",
        "aws_secret_access_key",
        "aws_access_key_id",
        "use_ssl",
    ]
    init_keys = {k: s3_out_struct.get(k) for k in keys if s3_out_struct.get(k)}

    _session = AioSession()
    exit_stack = AsyncExitStack()
    client_s3 = await create_aws_client(_session, exit_stack, auth_struct=init_keys)
    print("created Client for S3")

    s3 = dict()
    s3["init_keys"] = init_keys
    s3["client"] = client_s3
    s3["endpoint"] = s3_out_struct["endpoint"]
    s3["about_bucket"]: Dict = create_default_info_for_routes_bucket(s3)
    s3["output_file"] = file_with_result
    # endregion
    # region client sqs
    sqs_out_struct = {
        "service_name": "sqs",
        "region_name": os_environ.get("region_name_sqs", "ru-east-1"),
        "use_ssl": True,
        "endpoint_url": os_environ.get("endpoint_url_sqs"),
        "aws_secret_access_key": os_environ.get("aws_secret_access_key_sqs"),
        "aws_access_key_id": os_environ.get("aws_access_key_id_sqs"),
        "queue_url": os_environ.get("queuq_url_sqs"),
    }
    if sqs_out_struct["queue_url"]:  # TODO: rewrite checking settings
        keys = [
            "service_name",
            "endpoint_url",
            "region_name",
            "aws_secret_access_key",
            "aws_access_key_id",
            "use_ssl",
        ]
        init_keys = {k: sqs_out_struct.get(k) for k in keys if sqs_out_struct.get(k)}

        _session = AioSession()
        exit_stack = AsyncExitStack()
        client_sqs = await create_aws_client(
            _session, exit_stack, auth_struct=init_keys
        )
        print("created Client for SQS")
        sqs = dict()
        sqs["init_keys"] = init_keys
        sqs["client"] = client_sqs
        sqs["queue_url"] = sqs_out_struct["queue_url"]
    else:
        sqs = None
        print("mode about SQS - not enabled")
    # endregion
    return s3, sqs
