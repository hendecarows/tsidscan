#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
"""
    make channel config command

    Copyright (C) 2024 hendecarows
"""

import argparse
import inspect
import json
import logging
import sys
import traceback
import typing


class Logger:
    logger = None

    @classmethod
    def init(cls, log_name, log_level=logging.INFO):
        cls.logger = logging.getLogger(log_name)
        log_handler = logging.StreamHandler()
        log_handler.setLevel(log_level)
        cls.logger.setLevel(log_level)
        log_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s'
            )
        )
        cls.logger.addHandler(log_handler)

    @classmethod
    def error(cls, msg, *args, **kwargs):
        cls.logger.error(msg, *args, **kwargs)

    @classmethod
    def warning(cls, msg, *args, **kwargs):
        cls.logger.warning(msg, *args, **kwargs)

    @classmethod
    def info(cls, msg, *args, **kwargs):
        cls.logger.info(msg, *args, **kwargs)

    @classmethod
    def debug(cls, msg, *args, **kwargs):
        cls.logger.debug(msg, *args, **kwargs)

    @classmethod
    def trace_function(cls, msg=''):
        if msg:
            cls.logger.debug(
                '{} {}'.format(
                    inspect.currentframe().f_back.f_code.co_name,
                    msg
                )
            )
        else:
            cls.logger.debug(
                inspect.currentframe().f_back.f_code.co_name,
            )


class Config:

    def __init__(self, desc: str, isdb_s=True, isdb_t=True):
        self._ignores = set()
        self._args = self.parse_args(desc, isdb_s, isdb_t)
        self._configs = vars(self._args)

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self._args.input.close()
        self._args.output.close()

    def _parse_ignores(self, tsids: str):
        for tsid in tsids.split(','):
            self._ignores.add(int(tsid, 0))

    def parse_args(self, desc: str, isdb_s: bool=True, isdb_t: bool=True):
        parser = argparse.ArgumentParser(
            description=desc
        )
        parser.add_argument(
            '--log',
            help='log level. (error,warning,info,debug)',
            default='info',
            choices=['error', 'warning', 'info', 'debug'],
        )
        parser.add_argument(
            '--format',
            help='output format (dvbv5,bondvb,bonpt,bonptx,bonpx4)',
            default='dvbv5',
            choices=['dvbv5', 'bondvb', 'bonpt', 'bonptx', 'bonpx4'],
        )
        parser.add_argument(
            '--ignore',
            metavar='TSID1,TSID2...',
            help='ignore TSID1,TSID2,...',
            type=str,
            default='',
        )

        parser.add_argument(
            'input',
            help='input filename (stdin)',
            nargs='?',
            type=argparse.FileType('r', encoding='utf-8'),
            default='-',
        )
        parser.add_argument(
            'output',
            help='output filename (stdout)',
            nargs='?',
            type=argparse.FileType('w', encoding='utf-8'),
            default='-',
        )

        # parse
        args = parser.parse_args()

        # description
        args.description = desc

        # log level
        args.log_level = {
            'error': logging.ERROR,
            'warning': logging.WARNING,
            'info': logging.INFO,
            'debug':  logging.DEBUG,
        }[args.log]

        if args.ignore:
            self._parse_ignores(args.ignore)

        return args

    def get(self, option: str):
        return self._configs[option]

    def has_ignore_ts_id(self, tsid: int) -> bool:
        return tsid in self._ignores

    def format(self) -> str:
        return self._args.format

    def read(self) -> argparse.FileType:
        return self._args.input

    def write(self) -> argparse.FileType:
        return self._args.output


class Channel:

    def __init__(self, file: typing.TextIO):
        self._file = file
        self._func = {
            'dvbv5': self._dump_dvbv5,
            'bondvb': self._dump_bondvb,
            'bonpt': self._dump_bonpt,
            'bonptx': self._dump_bonptx,
            'bonpx4': self._dump_bonpx4,
        }

    def dump(self, format: str, results: json):
        self._func[format](results)

    def _dump_dvbv5(self, results: json):
        for t in ('BS', 'CS'):
            for r in results[t]:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if tsid == 0xffff:
                        continue
                    if 'BS' in r['transponder']:
                        self._file.write('[BS{:02d}_{}]\n'.format(r['number'], idx))
                    else:
                        self._file.write('[CS{}]\n'.format(r['number']))
                    self._file.write('\tDELIVERY_SYSTEM = ISDBS\n')
                    self._file.write('\tFREQUENCY = {}\n'.format(r['frequency_if_khz']))
                    self._file.write('\tSTREAM_ID = {}\n'.format(tsid))

    def _dump_bondvb(self, results: json):
        bonch = 0
        for t in ('BS', 'CS'):
            for r in results[t]:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if tsid == 0xffff:
                        continue
                    data = []
                    if 'BS' in r['transponder']:
                        data.append('BS{:02d}/TS{}'.format(r['number'], idx))
                    else:
                        data.append('ND{:02d}'.format(r['number']))
                    data.append(str(bonch))
                    data.append(str(r['frequency_idx']))
                    data.append('0x{:04x}'.format(tsid))
                    self._file.write('\t'.join(data))
                    self._file.write('\n')
                    bonch += 1


    def _dump_bonpt(self, results: json):
        bonch = 0
        for t in ('BS', 'CS'):
            for r in results[t]:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if tsid == 0xffff:
                        continue
                    data = []
                    if 'BS' in r['transponder']:
                        data.append('BS{:02d}/TS{}'.format(r['number'], idx))
                    else:
                        data.append('ND{:02d}'.format(r['number']))
                    data.append(str(bonch))
                    data.append(str(r['frequency_idx']))
                    data.append(str(idx))
                    self._file.write('\t'.join(data))
                    self._file.write('\n')
                    bonch += 1

    def _dump_bonptx(self, results: json):
        bonch = 0
        for t in ('BS', 'CS'):
            for r in results[t]:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if tsid == 0xffff:
                        continue
                    data = []
                    if 'BS' in r['transponder']:
                        data.append('Ch{}=BS{:02d}/TS{}'.format(bonch, r['number'], idx))
                        data.append(str(r['frequency_idx']))
                        data.append(str(idx))
                        self._file.write(','.join(data))
                        self._file.write('\n')
                        bonch += 1

    def _dump_bonpx4(self, results: json):
        bonchbs = 0
        bonchcs = 0
        for t in ('BS', 'CS'):
            for r in results[t]:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if tsid == 0xffff:
                        continue
                    data = []
                    if 'BS' in r['transponder']:
                        data.append('BS{:02d}/TS{}'.format(r['number'], idx))
                        data.append('0')
                        data.append(str(bonchbs))
                        bonchbs += 1
                    else:
                        data.append('ND{:02d}'.format(r['number']))
                        data.append('1')
                        data.append(str(bonchcs))
                        bonchcs += 1
                    data.append(str(r['frequency_idx']))
                    data.append(str(tsid))
                    self._file.write('\t'.join(data))
                    self._file.write('\n')


def main():

    with Config('make channel config command', isdb_s=True, isdb_t=False) as config:
        Logger.init(__name__, config.get('log_level'))
        try:
            results = json.load(config.read())
            # ignore TSID
            for t in ('BS', 'CS'):
                for r in results[t]:
                    if r['has_lock'] == False:
                        continue
                    for idx, tsid in enumerate(r['transport_stream_id']):
                        if tsid == 0xffff:
                            continue
                        if config.has_ignore_ts_id(tsid):
                            r['transport_stream_id'][idx] = 0xffff

            channel = Channel(config.write())
            channel.dump(config.format(), results)
        except Exception as e:
            Logger.error(e)


if __name__ == '__main__':
    try:
        main()
    except Exception as err:
        print(traceback.format_exc(), file=sys.stderr)
