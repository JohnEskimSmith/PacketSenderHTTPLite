#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "SAI"
__license__ = "GPLv3"
__status__ = "Dev"

import asyncio
import uvloop
import datetime
import ujson

from aiofiles import open as aiofiles_open
from typing import Optional, Tuple, List
from pathlib import Path
from os import unlink, environ as os_environ

from lib.workers import get_async_writer, create_io_reader, TargetReader, TaskProducer, Executor, OutputPrinter, \
    TargetWorker
from lib.util import parse_settings, parse_args, check_config_url, load_custom_worker, download_module
from lib.core import Stats, TargetConfig, AppConfig
from lib.serverless import parse_args_from_sqs_message, parse_cloud_env

DEFAULT_MODULES_DIR = 'modules'
DEFAULT_CUSTOM_MODULES_DIR = 'custom_modules'

PROJ_ROOT = Path(__file__).parent


async def main(target_settings: TargetConfig, config: AppConfig):
    # region cloud config
    s3_endpoint_env = os_environ.get('endpoint')
    cloud_s3_config, cloud_sqs_config = await parse_cloud_env(config.output_file, s3_endpoint=s3_endpoint_env)
    # endregion

    queue_input = asyncio.Queue()
    queue_tasks = asyncio.Queue()
    queue_prints = asyncio.Queue()
    #
    task_semaphore = asyncio.Semaphore(config.senders)
    statistics = Stats() if config.statistics else None
    #

    async with aiofiles_open(config.output_file, mode=config.write_mode) as file_with_results:
        writer_coroutine = get_async_writer(config)
        about_custom_module = config.custom_module
        directory_modules = DEFAULT_MODULES_DIR
        if config.url_custom_module:
            url_auth: Optional[Tuple] = check_config_url(config.url_custom_module)
            if url_auth:
                about_custom_module = await download_module(url_auth,
                                                            proj_root=PROJ_ROOT,
                                                            directory_modules=DEFAULT_CUSTOM_MODULES_DIR)
                directory_modules = DEFAULT_CUSTOM_MODULES_DIR
        if about_custom_module == 'default':
            target_worker = TargetWorker(statistics, task_semaphore, queue_prints, config)
        else:
            CustomWorker = load_custom_worker(about_custom_module, directory_modules)
            target_worker = CustomWorker(statistics, task_semaphore, queue_prints, config)

        input_reader: TargetReader = create_io_reader(statistics, queue_input, target_settings, config)
        task_producer = TaskProducer(statistics, queue_input, queue_tasks, target_worker)
        executor = Executor(statistics, queue_tasks, queue_prints)
        printer = OutputPrinter(config.output_file, statistics, queue_prints, file_with_results, writer_coroutine)

        running_tasks = [asyncio.create_task(worker.run())
                         for worker in [input_reader, task_producer, executor, printer]]
        await asyncio.wait(running_tasks)

    http_status = 0
    # region send file to S3 bucket
    data = None
    try:
        file_size = Path(config.output_file).stat().st_size
    except Exception as exp:
        print(exp, flush=True)
    else:
        if file_size > 0:
            with open(config.output_file, 'rb') as outfile:
                data = outfile.read()
    if data:
        client_s3 = cloud_s3_config['client']
        bucket = cloud_s3_config['about_bucket']['bucket']
        key_bucket = cloud_s3_config['about_bucket']['key']

        resp_from_s3 = await client_s3.put_object(Bucket=bucket,
                                                  Key=key_bucket,
                                                  Body=data)
        try:
            http_status = resp_from_s3['ResponseMetadata']['HTTPStatusCode']
        except Exception as exp:
            http_status = 0
            print(exp)
    # endregion

    try:
        await cloud_s3_config['client'].close()
    except Exception as e:
        print(e)
        print('errors when closing S3 Client connection')

    # need delete tmp file
    try:
        unlink(config.input_file)
        unlink(config.output_file)
    except:
        pass

    # region sending to sqs about file saved to buckets
    if cloud_sqs_config:
        if data:
            message_sqs = {'bucket': bucket,
                           'key': key_bucket,
                           'timestamp': int(datetime.datetime.now().timestamp())}

            body_message: str = ujson.dumps(message_sqs)
            status = await cloud_sqs_config['client'].send_message(QueueUrl=cloud_sqs_config['queue_url'],
                                                                   MessageBody=body_message)
            try:
                status_code: int = status['ResponseMetadata']['HTTPStatusCode']
                if status_code != 200:
                    print(f'SQS: errors: {status_code}')
                else:
                    print(f'SQS sent: {bucket}/{key_bucket}')
            except Exception as error_send:
                print(f'SQS: error: {error_send}')

        try:
            await cloud_sqs_config['client'].close()
        except Exception as e:
            print(e)
            print('errors when closing SQS Client connection')
    # endregion

    return http_status


def handler(event, context):
    raw_arguments: List[str] = parse_args_from_sqs_message(event)
    arguments = parse_args(raw_arguments)
    configs: Tuple[TargetConfig, AppConfig] = parse_settings(arguments)
    if arguments.use_uvloop:
        uvloop.install()
    s3_status = asyncio.run(main(*configs))
    return {'statusCode': 200,
            'body': s3_status}
