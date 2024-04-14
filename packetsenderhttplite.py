#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "SAI"
__license__ = "GPLv3"
__status__ = "Dev"

import asyncio
from pathlib import Path
from sys import version_info


import uvloop
from aiofiles import open as aiofiles_open


from lib.workers import get_async_writer, create_io_reader, TargetReader, TaskProducer, Executor, OutputPrinter, \
    TargetWorker
from lib.util import parse_settings, parse_args, check_config_url, load_custom_worker, download_module
from lib.core import Stats, TargetConfig, AppConfig

DEFAULT_MODULES_DIR = 'modules'
DEFAULT_CUSTOM_MODULES_DIR = 'custom_modules'

PROJ_ROOT = Path(__file__).parent


async def start(target_settings, config):

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
            url_auth: tuple | None = check_config_url(config.url_custom_module)
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


if __name__ == '__main__':
    arguments = parse_args()
    _configs: tuple[TargetConfig, AppConfig] = parse_settings(arguments)
    target_settings, config = _configs
    if arguments.use_uvloop:
        if version_info >= (3, 11):
            with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
                runner.run(start(target_settings, config))
        else:
            uvloop.install()
            start(target_settings, config)
    else:
        asyncio.run(start(target_settings, config))
