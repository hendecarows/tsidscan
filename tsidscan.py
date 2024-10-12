#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
"""
    scan tsid command

    Copyright (C) 2024 hendecarows
"""

import argparse
import inspect
import json
import logging
import math
import platform
import signal
import sys
import threading
import time
import traceback

import usb1


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

    @classmethod
    def to_hex(cls, data):
        try:
            if hasattr(data, '__iter__'):
                return ' '.join(['{:0>2x}'.format(x) for x in data])
            else:
                return '{:0>2x}'.format(data)
        except ValueError:
            return '{}'.format(data)

    @classmethod
    def get_usb_control_string(
        cls, request_type, request, value, index, length, data
    ):
        if request_type & 0x80:
            read_write = 'CR'
        else:
            read_write = 'CW'
        return '{} {:0>2x} {:0>2x} {:0>2x} {:0>2x} {:0>2x} {}'.format(
            read_write,
            request_type, request, value,
            index, length, cls.to_hex(data)
        )

    @classmethod
    def get_usb_bulk_string(cls, endpoint, data):
        if endpoint & 0x80:
            read_write = 'BR'
        else:
            read_write = 'BW'
        return '{} {:0>2x} {:0>2x} ; {}'.format(
            read_write, endpoint, len(data), cls.to_hex(data)
        )

    @classmethod
    def usb_control(
        cls, request_type, request, value, index, length, data,
        log_level=logging.DEBUG
    ):
        msg = cls.get_usb_control_string(
            request_type, request, value, index, length, data
        )
        if log_level == logging.ERROR:
            cls.error(msg)
        elif log_level == logging.DEBUG:
            cls.debug(msg)

    @classmethod
    def usb_bulk(cls, endpoint, data, log_level=logging.DEBUG):
        msg = cls.get_usb_bulk_string(endpoint, data)
        if log_level == logging.ERROR:
            cls.error(msg)
        elif log_level == logging.DEBUG:
            cls.debug(msg)


class Config:

    def __init__(self, desc: str, isdb_s=True, isdb_t=True):
        self._args = self.parse_args(desc, isdb_s, isdb_t)
        self._configs = vars(self._args)

    def parse_args(self, desc: str, isdb_s: bool=True, isdb_t: bool=True):
        parser = argparse.ArgumentParser(
            description=desc
        )
        parser.add_argument(
            '--log',
            help='log level (error,warning,info,debug)',
            default='info',
            choices=['error', 'warning', 'info', 'debug'],
        )
        parser.add_argument(
            '--log-usb',
            help='libusb log level (error,warning,info,debug)',
            default='info',
            choices=['error', 'warning', 'info', 'debug'],
        )
        parser.add_argument(
            '--device',
            help='use device (1t1s,isdb2056,m1ur)',
            default='',
            choices=['1t1s', 'isdb2056', 'm1ur',],
        )
        parser.add_argument(
            '--vid',
            help='usb vendor id',
            type=lambda x: int(x,0), default=0x0511,
        )
        parser.add_argument(
            '--pid',
            help='usb product id',
            type=lambda x: int(x,0), default=0x004b,
        )
        parser.add_argument(
            '--bus-no',
            help='usb bus no.',
            type=int, default=0,
        )
        parser.add_argument(
            '--device-address',
            help='usb device address',
            type=int, default=0,
        )
        parser.add_argument(
            '--firmware',
            help='firmware file',
            default='/lib/firmware/it930x-firmware.bin',
        )

        parser.add_argument(
            'output',
            help='output filename (stdout)',
            nargs='?',
            type=argparse.FileType('w'),
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

        # libusb log level
        args.log_level_usb = {
            'error': usb1.LOG_LEVEL_ERROR,
            'warning': usb1.LOG_LEVEL_WARNING,
            'info': usb1.LOG_LEVEL_INFO,
            'debug':  usb1.LOG_LEVEL_DEBUG,
        }[args.log_usb]

        # device
        vidpids = {
            '1t1s': (0x0511, 0x004b),
            'isdb2056': (0x0511, 0x004b),
            'm1ur': (0x0511, 0x0854),
        }
        if args.device:
            args.vid = vidpids[args.device][0]
            args.pid = vidpids[args.device][1]

        return args

    def get(self, option: str):
        return self._configs[option]

    def write(self) -> argparse.FileType:
        return self._args.output

class TunerDevice:
    """
        DTV02-1T1S-U : Digibest
        vendor id    : 0x0511
        product id   : 0x004b
        usb bridge   : ITE Tech IT9303
        demodulator  : TOSHIBA TC90532
        tuner isdb-s : RafaelMicro RT710
        tuner isdb-t : RafaelMicro R850
    """

    # tuner type
    ISDB_S = 0
    ISDB_T = 1

    # target device
    ISDB_S0 = 0
    ISDB_T0 = 1

    TARGET_CONFIG = [
        # ISDB_S0
        {
            'tuner_type': ISDB_S,
            'i2c_bus_no': 0x03,
            'demodulator_address': 0x22,
            'tuner_address': 0xf4,
            'pair_target': ISDB_T0,
        },
        # ISDB_T0
        {
            'tuner_type': ISDB_T,
            'i2c_bus_no': 0x03,
            'demodulator_address': 0x20,
            'tuner_address': 0xf8,
            'pair_target': ISDB_S0,
        }
    ]

    TS_PACKET_SIZE = 188

    ENDPOINT_IN = 0x81
    ENDPOINT_OUT = 0x02
    ENDPOINT_TS = 0x84
    ENDPOINT_TS_TRANSFER_LENGTH = 0x95d0  # 38352
    ENDPOINT_TS_PACKET_SIZE = 0x80  # USB20_MAX_PACKET_SIZE/4 = 512/4 = 128

    BULK_TRANSFER_COUNT = 16
    BULK_TRANSFER_SIZE = 0x25740  # 153408
    BULK_TRANSFER_TIMEOUT = 1500

    MAX_COUNT_SET_CHANNEL_S = 1
    MAX_COUNT_LOCK_TUNER_S = 10
    MAX_COUNT_LOCK_DEMODULATOR_S = 10
    MAX_COUNT_LOCK_RLOCK_S = 10
    MAX_COUNT_LOCK_TS_ID_S = 30

    def __init__(self, config):
        self._config = config
        self._sequence = -1
        self._chip_id = 0
        self._firmware_version = 0
        self._is_init_device = False
        self._is_start_stream = False
        self._usb_context = None
        self._usb_handle = None
        self._usb_transfer_list = []

    @property
    def sequence(self):
        self._sequence += 1
        if self._sequence > 0xff:
            self._sequence = 0
        return self._sequence

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, exception_traceback):
        self.close()

    def get_config(self, key):
        return self._config.get(key)

    def bit_flag(self, value, bit_position_from_zero, is_set=True):
        is_bit_set = False
        bit = 1 << bit_position_from_zero
        if value & bit:
            is_bit_set = True
        if is_bit_set == is_set:
            return True
        else:
            return False

    def bit_set(self, value, bit_position_from_zero, is_set):
        bit = 1 << bit_position_from_zero
        if is_set:
            return value | bit
        else:
            return value & (~bit)

    def bit_set_length(self, value, bit_position_from_zero, length, is_set):
        for i in range(length):
            value = self.bit_set(value, bit_position_from_zero + i, is_set)
        return value

    def bit_reverse(self, value: int) -> int:
        t = value & 0xff
        t = ((t & 0x55) << 1) | ((t & 0xaa) >> 1)
        t = ((t & 0x33) << 2) | ((t & 0xcc) >> 2)
        t = ((t & 0x0f) << 4) | ((t & 0xf0) >> 4)
        return t

    def get_targets(self):
        yield self.ISDB_S0
        yield self.ISDB_T0

    def get_tuner_type(self, target: int):
        return self.TARGET_CONFIG[target]['tuner_type']

    def get_i2c_bus_no(self, target: int):
        return self.TARGET_CONFIG[target]['i2c_bus_no']

    def get_address_demodulator(self, target: int):
        return self.TARGET_CONFIG[target]['demodulator_address']

    def get_address_tuner(self, target: int, is_read: bool=False):
        address = self.TARGET_CONFIG[target]['tuner_address']
        if is_read:
            # lsb = 1 by reading
            address = self.bit_set(address, 0, True)
        return address

    def get_pair_target(self, target: int):
        return self.TARGET_CONFIG[target]['pair_target']

    def open_usb_device(self):
        Logger.trace_function()
        if self._usb_handle:
            return

        vid = self.get_config('vid')
        pid = self.get_config('pid')
        bus_no = self.get_config('bus_no')
        device_address = self.get_config('device_address')
        log_level = self.get_config('log_level_usb')
        context = usb1.USBContext()
        context.setDebug(log_level)
        for device in context.getDeviceIterator(skip_on_error=True):
            handle = None
            if device.getVendorID() != vid:
                continue
            if device.getProductID() != pid:
                continue
            if bus_no > 0:
                if device.getBusNumber() != bus_no:
                    continue
            if device_address > 0:
                if device.getDeviceAddress() != device_address:
                    continue
            try:
                handle = device.open()
                handle.claimInterface(0)
                break
            except Exception as err:
                Logger.debug(err)

        msg = 'vid=0x{:0>4x} pid=0x{:0>4x} bus={} address={}'.format(
            vid, pid, bus_no, device_address
        )
        if handle:
            Logger.debug('open usb device %s', msg)
        else:
            context.close()
            raise RuntimeError(
                'fail to open usb device {}'.format(msg)
            )

        self._usb_context = context
        self._usb_handle = handle

    def close_usb_device(self):
        Logger.trace_function()
        if not self._usb_handle:
            return

        self._usb_handle.close()
        self._usb_context.close()
        self._usb_handle = None
        self._usb_context = None

    def get_checksum(self, buffer, omit_last_bytes=0, start_byte=1):
        size = len(buffer) - omit_last_bytes
        checksum = 0
        for i in range(start_byte, size):
            if i % 2 != 0:
                checksum += buffer[i] << 8
            else:
                checksum += buffer[i]
        checksum = ~checksum
        return checksum & 0xffff

    def add_checksum(self, buffer):
        checksum = self.get_checksum(buffer)
        # last 2bytes : checksum
        buffer.append((checksum >> 8) & 0xff)
        buffer.append(checksum & 0xff)
        # first byte : buffer length
        buffer[0] = len(buffer) - 1

    def write_command_usb_bridge(
        self, command: int, write_data, read_length: int, wait: float=0
    ):
        """write command to usb bridge

           Write and read are pair.
           Bulk write        : 0b 00 00 00 01 02 00 00 12 22 db ec
           Bulk read         : 05 00 00 01 fe ff

           [0] 0b            : data length from [1] to [11]
           [1-2] 00 00       : command
           [3] 00            : sequence number 00 to ff
           [4] 01            : read or write length
           [5] 02            : read or write address length
           [6-9] 00 00 12 22 : read or write address
           [10-11] db ec     : checksum from [1] to [9]

           [0] 05            : data length from [1] to [5]
           [1] 00            : sequence number
           [2] 00            : error code 0 is no error
           [3] 01            : read data
           [4-5] fe ff       : checksum from [1] to [3]
        """
        # write data
        write_buffer = [
            0,  # write buffer length
            (command >> 8) & 0xff,
            command & 0xff,
            self.sequence,
        ]
        if hasattr(write_data, '__iter__'):
            write_buffer.extend(write_data)
        else:
            if write_data is None:
                pass
            else:
                write_buffer.append(write_data)
        self.add_checksum(write_buffer)
        endpoint = self.ENDPOINT_OUT
        Logger.usb_bulk(endpoint, write_buffer)
        write_length = self._usb_handle.bulkWrite(
            endpoint, bytes(write_buffer),
            timeout=self.BULK_TRANSFER_TIMEOUT
        )
        if write_length != len(write_buffer):
            Logger.usb_bulk(endpoint, write_buffer, logging.ERROR)
            raise RuntimeError(
                'mismatch transfer length {:x} != {:x}'.format(
                    len(write_buffer), write_length
                )
            )

        # wait
        if wait > 0:
            time.sleep(wait)

        # read status
        add_length = 5
        endpoint = self.ENDPOINT_IN
        read_data = self._usb_handle.bulkRead(
            endpoint, read_length + add_length,
            timeout=self.BULK_TRANSFER_TIMEOUT
        )
        Logger.usb_bulk(endpoint, read_data)
        # check error
        if read_data[2] != 0:
            Logger.usb_bulk(endpoint, read_data, logging.ERROR)
            raise RuntimeError(
                'command error status code : {:x}'.format(read_data[2])
            )

        # last 2 bytes : checksum
        tmpsum = int.from_bytes(read_data[-2:], 'big')
        checksum = self.get_checksum(read_data, omit_last_bytes=2)
        if checksum != tmpsum:
            Logger.usb_bulk(endpoint, read_data, logging.ERROR)
            raise RuntimeError(
                'invalid checksum {:x} != {:x}'.format(checksum, tmpsum)
            )
        read_data_length = len(read_data) - add_length
        if read_data_length == 1:
            return read_data[3]
        elif read_data_length > 1:
            return read_data[3:-2]
        else:
            return None

    def read_usb_bridge(self, read_address: int, read_length: int=1, wait: float=0):
        """read value from usb bridge register

           Bulk write        : 0b 00 00 00 01 02 00 00 12 22 db ec
           Bulk read         : 05 00 00 01 fe ff

           [0] 0b            : data length from [1] to [11]
           [1-2] 00 00       : command
           [3] 00            : sequence number 00 to ff
           [4] 01            : read length
           [5] 02            : read address length
           [6-9] 00 00 12 22 : read address
           [10-11] db ec     : checksum from [1] to [9]

           [0] 05            : data length from [1] to [5]
           [1] 00            : sequence number
           [2] 00            : error code 0 is no error
           [3] 01            : read data
           [4-5] fe ff       : checksum from [1] to [3]
        """
        # 0x0000 : read register
        command = 0x0000
        if read_address > 0xff:
            read_address_length = 2
        else:
            read_address_length = 1
        write_buffer = [
            read_length,
            read_address_length,
        ]
        # append 4 bytes read address
        write_buffer.extend(read_address.to_bytes(4, 'big'))
        # write command
        return self.write_command_usb_bridge(
            command, write_buffer, read_length, wait
        )

    def write_usb_bridge(self, write_address: int, write_data, wait: float=0):
        """write value to usb bridge register

           Bulk write        : 0c 00 01 2c 01 02 00 00 49 76 00 5b b4
           Bulk read         : 04 2c 00 d3 ff

           [0] 0c            : data length from [1] to [12]
           [1-2] 00 01       : command
           [3] 2c            : sequence number 00 to ff
           [4] 01            : write data length
           [5] 02            : write address length
           [6-9] 00 00 49 76 : write address
           [10] 00           : write data
           [11-12] 5b b4     : checksum from [1] to [10]

           [0] 04            : data length from [1] to [4]
           [1] 2c            : sequence number
           [2] 00            : error code 0 is no error
           [3-4] d3 ff       : checksum from [1] to [2]
        """
        # 0x0001 : write register
        command = 0x0001
        # write data length
        if isinstance(write_data, int):
            write_data_length = 1
            write_data = [write_data, ]
        elif hasattr(write_data, '__iter__'):
            write_data_length = len(write_data)
        else:
            raise RuntimeError(
                'invalid write data to usb bridge {}'.format(
                    write_data
                )
            )
        # write address length
        write_address_length = 1
        if write_address & 0xff000000:
            write_address_length = 4
        elif write_address & 0xff0000:
            write_address_length = 3
        elif write_address & 0xff00:
            write_address_length = 2

        write_buffer = [
            write_data_length,
            write_address_length,
        ]
        # append 4 bytes write address
        write_buffer.extend(write_address.to_bytes(4, 'big'))
        # append write data
        write_buffer.extend(write_data)
        # write command (read_length = 0)
        self.write_command_usb_bridge(command, write_buffer, 0, wait)

    def write_data_usb_bridge(self, write_data, wait: float=0):
        """sequential write value to usb bridge register

           write_data = (
               (address, values),
               (None, seconds),  # sleep seconds
           )
        """
        for data in write_data:
            if data[0] is None:
                time.sleep(data[1])
                continue
            self.write_usb_bridge(data[0], data[1:], wait)

    def write_bit_usb_bridge(
        self, write_address: int, write_position: int, write_length: int, is_set: bool
    ):
        """write bit value to usb bridge register
        """
        read_data = self.read_usb_bridge(write_address)
        write_data = self.bit_set_length(
            read_data, write_position, write_length, is_set
        )
        self.write_usb_bridge(write_address, write_data)

    def read_demodulator(
        self, target: int, read_address: int, through_address=None, read_length: int=1
    ):
        """read value from demodulator register

           write 0x01 to p_br_reg_repeat_start = 0xf424
           Bulk write        : 0c 00 01 91 01 02 00 00 f4 24 01 48 08
           Bulk read         : 04 91 00 6e ff

           write demodulator register address 0xc3 to read
           Bulk write        : 09 00 2b 92 01 03 22 c3 a7 b1
           Bulk read         : 04 92 00 6d ff

           [0] 09            : data length from [1] to [9]
           [1-2] 00 2b       : command i2c write
           [3] 92            : sequence number 00 to ff
           [4] 01            : write data length
           [5] 03            : i2c bus no.
           [6] 22            : i2c slave address of demodulator
           [7] c3            : register address of demodulator
           [8-9] a7 b1       : checksum from [1] to [7]

           write 0x00 to p_br_reg_repeat_start = 0xf424
           Bulk write        : 0c 00 01 93 01 02 00 00 f4 24 00 46 09
           Bulk read         : 04 93 00 6c ff

           read from address 0xc3
           Bulk write        : 08 00 2a 94 01 03 22 68 b2
           Bulk read         : 05 94 00 00 6b ff

           [0] 08            : data length from [1] to [8]
           [1-2] 00 2a       : command i2c read
           [3] 94            : sequence number 00 to ff
           [4] 01            : read data length
           [5] 03            : i2c bus no.
           [6] 22            : i2c slave address of demodulator
           [7-8] 68 b2       : checksum from [1] to [6]

           [0] 05            : data length from [1] to [5]
           [1] 94            : sequence number
           [2] 00            : error code 0 is no error
           [3] 00            : read data
           [4-5] 6b ff       : checksum from [1] to [3]
        """
        # p_br_reg_repeat_start = 0xf424
        # self.write_usb_bridge(0xf424, 0x01)
        # write address to read
        self.write_demodulator(target, read_address, through_address)
        # p_br_reg_repeat_start = 0xf424
        # self.write_usb_bridge(0xf424, 0x00)

        # generic read
        command = 0x002a
        i2c_bus_no = self.get_i2c_bus_no(target)
        address_demod = self.get_address_demodulator(target)
        write_buffer = [
            read_length,
            i2c_bus_no,
            address_demod,
        ]

        # write command
        return self.write_command_usb_bridge(
            command, write_buffer, read_length
        )

    def write_demodulator(self, target: int, write_address: int, write_data):
        """write value to demodulator register

           Bulk write        : 0a 00 2b c4 02 03 20 b0 a0 88 12
           Bulk read         : 04 c4 00 3b ff

           [0] 0a            : data length from [1] to [10]
           [1-2] 00 2b       : command i2c write
           [3] c4            : sequence number 00 to ff
           [4] 02            : write data length
           [5] 03            : i2c bus no.
           [6] 20            : i2c slave address of demodulator
           [7] b0            : register address of demodulator
           [8] a0            : write data
           [9-10] 88 12      : checksum from [1] to [8]

           [0] 04            : data length from [1] to [4]
           [1] c4            : sequence number
           [2] 00            : error code 0 is no error
           [3-4] 3b ff       : checksum from [1] to [2]
        """
        # i2c write
        command = 0x002b
        # write data length
        if isinstance(write_data, int):
            write_data_length = 2
            write_data = [write_data, ]
        elif write_data is None:
            write_data_length = 1
            write_data = []
        elif hasattr(write_data, '__iter__'):
            write_data_length = len(write_data) + 1
        i2c_bus_no = self.get_i2c_bus_no(target)
        address_demod = self.get_address_demodulator(target)
        write_buffer = [
            write_data_length,
            i2c_bus_no,
            address_demod,
            write_address,
        ]
        # append write data
        write_buffer.extend(write_data)
        # write command (read_length = 0)
        self.write_command_usb_bridge(command, write_buffer, 0)

    def write_data_demodulator(self, write_data):
        """sequential write value to demodulator register

           write_data = (
               (target, address, values),
               (None, seconds),  # sleep seconds
           )
        """
        for data in write_data:
            if data[0] is None:
                time.sleep(data[1])
                continue
            self.write_demodulator(data[0], data[1], data[2:])

    def read_tuner(self, target: int, read_address: int, read_length: int=1, is_reverse: bool=True):
        """read value from tuner register

           write 0x01 to p_br_reg_repeat_start = 0xf424

           through write demodulator address 0xfe and tuner address 0xf5
           (0xf4 | 0x01)
           Bulk write        : 0a 00 2b 05 02 03 22 fe f5 f8 bb
           Bulk read         : 04 05 00 fa ff

           [0] 0a            : data length from [1] to [10]
           [1-2] 00 2b       : command i2c write
           [3] 05            : sequence number 00 to ff
           [4] 02            : write data length
           [5] 03            : i2c bus no.
           [6] 22            : i2c slave address of demodulator
           [7] fe            : i2c slave address of tuner
           [8] f5            : register address of tuner
           [9-10] f8 bb      : checksum from [1] to [6]

           write 0x00 to p_br_reg_repeat_start = 0xf424

           read read_length bytes from tuner first address 0xf5
           Bulk write        : 08 00 2a 07 04 03 22 f5 af
           Bulk read         : 08 07 00 69 38 00 5e 8f 69

           [0] 08            : data length from [1] to [8]
           [1-2] 00 2a       : command i2c read
           [3] 07            : sequence number 00 to ff
           [4] 04            : read data length
           [5] 03            : i2c bus no.
           [6] 22            : i2c slave address of demodulator
           [7-8] f5 af       : checksum from [1] to [6]

           [0] 08            : data length from [1] to [9]
           [1] 07            : sequence number
           [2] 00            : error code 0 is no error
           [3-6] 69 38 00 5e : read read_length bytes from address 0xf5
           [7-8] 8f 69       : checksum from [1] to [4]
        """

        # read
        # address_tuner = self.get_address_tuner(target, False)
        # write_data = [
        #     address_tuner,
        #     0x00,
        # ]
        # self.write_demodulator(target, 0xfe, write_data)
        # i2c through read mode
        self.write_tuner(target, 0x00, None)
        address_tuner = self.get_address_tuner(target, True)
        read_length_reg0 = read_address + read_length
        read_data = self.read_demodulator(
            target, 0xfe, address_tuner, read_length_reg0
        )
        if isinstance(read_data, int):
            if is_reverse:
                read_data = self.bit_reverse(read_data)
        else:
            read_data = read_data[read_address:]
            if is_reverse:
                for i, v in enumerate(read_data):
                    read_data[i] = self.bit_reverse(v)
                if len(read_data) == 1:
                    read_data = read_data[0]
        return read_data

    def write_tuner(self, target: int, write_address: int, write_data):
        """write value to tuner register

           Bulk write        : 0c 00 2b 09 04 03 22 fe f4 04 40 f0 7a
           Bulk read         : 04 09 00 f6 ff

           [0] 0c            : data length from [1] to [12]
           [1-2] 00 2b       : command i2c write
           [3] 09            : sequence number 00 to ff
           [4] 04            : write data length
           [5] 03            : i2c bus no.
           [6] 22            : i2c slave address of demodulator
           [7] fe            : through write address of demodulator
           [8] f4            : i2c slave address of tuner
           [9] 04            : write address
           [10] 40           : write data
           [11-12] f0 7a     : checksum from [1] to [10]

           [0] 04            : data length from [1] to [4]
           [1] 09            : sequence number
           [2] 00            : error code 0 is no error
           [3-4] f6 ff       : checksum from [1] to [2]
        """
        address_tuner = self.get_address_tuner(target)
        if isinstance(write_data, int):
            write_data = [write_data, ]
        elif write_data is None:
            write_data = []
        write_buffer = [
            address_tuner,
            write_address,
        ]
        # append write data
        write_buffer.extend(write_data)
        # i2c through write mode
        self.write_demodulator(target, 0xfe, write_buffer)

    def write_data_tuner(self, write_data):
        """sequential write value to tuner register

           write_data = (
               (target, address, values),
               (None, seconds),  # sleep seconds
           )
        """
        for data in write_data:
            if data[0] is None:
                time.sleep(data[1])
                continue
            self.write_tuner(data[0], data[1], data[2:])

    def is_load_firmware(self) -> bool:
        if self._firmware_version:
            return True
        else:
            return False

    def get_chip_id(self) -> int:
        Logger.trace_function()

        # chip_version_7_0 = 0x1222
        read_data = self.read_usb_bridge(0x1222, 3)
        chip_id = int.from_bytes(read_data[1:], 'little')
        Logger.debug('chip id = %x', chip_id)
        chip_version = read_data[0]
        Logger.debug('chip version = %x', chip_version)

        # prechip_version_7_0 = 0x384f
        read_data = self.read_usb_bridge(0x384f, 1)
        Logger.debug('prechip version = %x', read_data)

        self._chip_id = (chip_id << 16) | (read_data << 8) | chip_version
        Logger.debug('chip id = %x', self._chip_id)
        return self._chip_id

    def get_firmware_version(self) -> int:
        Logger.trace_function()

        # Command_QUERYINFO = 0x0022
        # Write Data = 1, Read Length = 4
        read_data = self.write_command_usb_bridge(0x0022, 1, 4)
        version = int.from_bytes(read_data, 'big')
        Logger.debug('firmware version = %x', version)
        self._firmware_version = version
        return self._firmware_version

    def load_firmware(self):
        Logger.trace_function()

        # read firmware
        try:
            filename = self.get_config('firmware')
            Logger.debug('firmware file = %s', filename)
            with open(filename, 'rb') as file:
                firmware = file.read()
        except Exception as e:
            Logger.info('fail to open firmware file = %s', filename)
            return

        # clear i2c address and bus settings in firmware
        # second_i2c_bus = 0x4976
        # second_i2c_address = 0x4bfb
        # third_i2c_address = 0x4978
        # fourth_i2c_address = 0x4977
        # set i2c master clock speed
        # p_br_reg_cycle_counter_tuner = 0xf103
        # IT9300User_I2C_SPEED = 0x07
        write_data = (
            (0x4976, 0x00),
            (0x4bfb, 0x00),
            (0x4978, 0x00),
            (0x4977, 0x00),
            (0xf103, 0x07),
        )
        self.write_data_usb_bridge(write_data)

        # firmware
        # header      | block1   | block2   | block3   |
        # 03 00 00 03 | 41 00 03 | 41 80 06 | 41 93 1a |
        # block1 data | block2 data | block3 data
        # 03 bytes    | 06 bytes    | 1a bytes
        #
        # header
        # 03
        # 00
        # 00
        # 03 : block size
        #
        # block1
        # 41 00 : block address
        # 03    : block data size
        # block2
        # 41 80 : block address
        # 06    : block data size
        # block3
        # 41 93 : block address
        # 1a    : block data size

        iend = 0
        while iend < len(firmware):
            i = ibegin = iend
            if firmware[i] != 0x03:
                raise RuntimeError(
                    'invalid firmware header index = {}'.format(i)
                )
            i += 3
            block_size = firmware[i]
            block_data_size = 0
            for _ in range(block_size):
                i += 3
                block_data_size += firmware[i]

            # header = 4, address + block data size = 2 + 1 = 3
            iend = ibegin + 4 + 3 * block_size + block_data_size

            # Command_SCATTER_WRITE = 0x0029
            self.write_command_usb_bridge(0x0029, firmware[ibegin:iend], 0)

        # reboot
        # Command_BOOT = 0x0023
        Logger.debug('boot firmware')
        self.write_command_usb_bridge(0x0023, None, 0)

        # sleep 20msec
        time.sleep(0.02)

        # validate load firmware
        self.get_firmware_version()
        if not self.is_load_firmware():
            raise RuntimeError('fail to load firmware')

    def set_gpio(self, port_no, is_high):
        Logger.trace_function('gpio port={} high={}'.format(port_no, is_high))

        gpio_regs = [
            0xd8b0,  # gpioh1
            0xd8b8,  # gpioh2
            0xd8b4,  # gpioh3
            0xd8c0,  # gpioh4
            0xd8bc,  # gpioh5
            0xd8c8,  # gpioh6
            0xd8c4,  # gpioh7
            0xd8d0,  # gpioh8
            0xd8cc,  # gpioh9
            0xd8d8,  # gpioh10
            0xd8d4,  # gpioh11
            0xd8e0,  # gpioh12
            0xd8dc,  # gpioh13
            0xd8e4,  # gpioh14
            0xd8e8,  # gpioh15
            0xd8ec,  # gpioh16
        ]

        reg = gpio_regs[port_no - 1]
        if is_high:
            val = 0x01
        else:
            val = 0x00

        # p_br_reg_top_gpiohx_o = 0x01 or 0x00
        # p_br_reg_top_gpiohx_en = 0x01
        # p_br_reg_top_gpiohx_on = 0x01
        write_data = (
            (reg - 0x01, val),
            (reg, 0x01),
            (reg + 0x01, 0x01),
        )
        self.write_data_usb_bridge(write_data, wait=0.01)

    def init_usb_bridge(self):
        Logger.trace_function()

        # set i2c master bus 2 clock speed 300k
        # p_br_reg_lnkofdm_data_36_56 = 0xf6a7
        # set i2c master bus 1,3 clock speed 300k
        # p_br_reg_cycle_counter_tuner = 0xf103
        # p_br_mp2if_ignore_sync_byte = 0xda1a
        write_data = (
            (0xf6a7, 0x07),
            (0xf103, 0x07),
            (0xda1a, 0x00),
        )
        self.write_data_usb_bridge(write_data)

        self.init_output_ts_type_usb_bridge()
        self.init_config_output_usb_bridge()

        # p_br_reg_top_host_reverse = 0xd920
        # p_br_reg_top_padmiscdrsr = 0xd833
        # p_br_reg_top_padmiscdr2 = 0xd830
        # p_br_reg_top_padmiscdr4 = 0xd831
        # p_br_reg_top_padmiscdr8 = 0xd832
        write_data = (
            (0xd920, 0x00),
            (0xd833, 0x01),
            (0xd830, 0x00),
            (0xd831, 0x01),
            (0xd832, 0x00),
        )
        self.write_data_usb_bridge(write_data)

        # second_demod_i2c_bus = 0x4976
        # next_level_first_i2c_address = 0x4975
        # next_level_first_i2c_bus = 0x4971
        write_data = (
            # (0x4976, 0x01),
            (0x4975, 0x22),
            (0x4971, 0x03),
            (0x4974, 0x20),
            (0x4970, 0x03),
        )
        self.write_data_usb_bridge(write_data)

        # gpio h11(0xd8d4),h2(0xd8b8)
        self.set_gpio(11, True)
        self.set_gpio(2, True)

        # r_br_mp2if_psb_count_12_8 = 0xda99
        # r_br_mp2if_psb_count_7_0 = 0xda98
        self.read_usb_bridge(0xda99)
        self.read_usb_bridge(0xda98)

        self.init_sync_byte_mode_usb_bridge()

        # Command_UART_SET_MODE = 0x0037
        # self.write_command_usb_bridge(0x0037, 0x01, 0)

    def init_output_ts_type_usb_bridge(self):
        Logger.trace_function()

        # Enbale DVB-T interrupt
        # p_br_reg_dvbt_inten = 0xf41f
        # br_reg_dvbt_inten_pos = 2
        # br_reg_dvbt_inten_len = 1
        self.write_bit_usb_bridge(0xf41f, 2, 1, True)

        # p_br_reg_mpeg_full_speed = 0xda10
        # br_reg_mpeg_full_speed_pos = 0
        # br_reg_mpeg_full_speed_len = 1
        self.write_bit_usb_bridge(0xda10, 0, 1, False)

        # Enable DVB-T mode
        # p_br_reg_dvbt_en = 0xf41a
        # br_reg_dvbt_en_pos = 0
        # br_reg_dvbt_inten_len = 1
        self.write_bit_usb_bridge(0xf41a, 0, 1, True)

    def init_config_output_usb_bridge(self):
        Logger.trace_function()

        # Reset EP4
        # p_br_reg_mp2_sw_rst = 0xda1d
        # br_reg_mp2_sw_rst_pos = 0
        # br_reg_mp2_sw_rst_len = 1
        self.write_bit_usb_bridge(0xda1d, 0, 1, True)

        # Disable EP4
        # p_br_reg_ep4_tx_en = 0xdd11
        # br_reg_ep4_tx_en_pos = 5
        # br_reg_ep4_tx_en_len = 1
        self.write_bit_usb_bridge(0xdd11, 5, 1, False)

        # Disable EP4 NAK
        # p_br_reg_ep4_tx_nak = 0xdd13
        # br_reg_ep4_tx_nak_pos = 5
        # br_reg_ep4_tx_nak_len = 1
        self.write_bit_usb_bridge(0xdd13, 5, 1, False)

        # Enable EP4
        # p_br_reg_ep4_tx_en = 0xdd11
        # br_reg_ep4_tx_en_pos = 5
        # br_reg_ep4_tx_en_len = 1
        self.write_bit_usb_bridge(0xdd11, 5, 1, True)

        # Set EP4 transfer length
        # p_br_reg_ep4_tx_len_7_0 = 0xdd88
        write_data = [
            self.ENDPOINT_TS_TRANSFER_LENGTH & 0xff,
            (self.ENDPOINT_TS_TRANSFER_LENGTH >> 8) & 0xff,
        ]
        self.write_usb_bridge(0xdd88, write_data)

        # Set EP4 packet size
        # p_br_reg_ep4_max_pkt = 0xdd0c
        self.write_usb_bridge(0xdd0c, self.ENDPOINT_TS_PACKET_SIZE)

        # Disable 15 SER/PAR mode
        # p_br_mp2if_mpeg_ser_mode = 0xda05
        # br_mp2if_mpeg_ser_mode_pos = 0
        # br_mp2if_mpeg_ser_mode_len = 1
        self.write_bit_usb_bridge(0xda05, 0, 1, False)

        # p_br_mp2if_mpeg_par_mode = 0xda06
        # br_mp2if_mpeg_par_mode_pos = 0
        # br_mp2if_mpeg_par_mode_len = 1
        self.write_bit_usb_bridge(0xda06, 0, 1, False)

        # Negate EP4 reset
        # p_br_reg_mp2_sw_rst = 0xda1d
        # br_reg_mp2_sw_rst_pos = 0
        # br_reg_mp2_sw_rst_len = 1
        self.write_bit_usb_bridge(0xda1d, 0, 1, False)

    def init_sync_byte_mode_usb_bridge(self):
        Logger.trace_function()

        # p_br_reg_ts0_en = 0xda4c to 0xda50 : ts0 to ts5
        # p_br_reg_ts_in_src = 0xda58,0xda59 : ts0 to ts1
        # p_br_reg_ts0_aggre_mode = 0xda73 to 0xda77 : ts0 to ts5
        # p_br_reg_ts0_sync_byte = 0xda78 to 0xda7c : ts0 to ts5
        write_data = (
            (0xda4c, 0x01),
            (0xda4d, 0x00),
            (0xda4e, 0x00),
            (0xda4f, 0x00),
            (0xda50, 0x00),

            (0xda58, 0x00),
            (0xda59, 0x00),

            (0xda73, 0x01),
            (0xda74, 0x00),
            (0xda75, 0x00),
            (0xda76, 0x00),
            (0xda77, 0x00),

            (0xda78, 0x47),
            (0xda79, 0x27),
            (0xda7a, 0x37),
            (0xda7b, 0x17),
            (0xda7c, 0x57),
        )
        self.write_data_usb_bridge(write_data)

    def set_sleep_usb_bridge(self, is_sleep: int):
        Logger.trace_function('sleep={}'.format(is_sleep))

        if is_sleep:
            self.set_gpio(2, False)
            self.set_gpio(3, True)
        else:
            self.set_gpio(3, False)
            time.sleep(0.01)
            self.set_gpio(2, True)

    def set_system_reset_demodulator(self, target: int):
        Logger.trace_function('target={}'.format(target))

        tuner_type = self.get_tuner_type(target)
        if tuner_type == self.ISDB_S:
            write_data = (
                (target, 0x01, 0x90),  # psksyrst=1
                (None, 0.01),          # sleep 0.01sec
            )
        else:
            write_data = (
                (target, 0x01, 0x80),  # isysrst=1
                (None, 0.01),          # sleep 0.01sec
            )
        self.write_data_demodulator(write_data)

    def set_sleep_demodulator(self, target: int, is_sleep: bool):
        Logger.trace_function('target={} sleep={}'.format(target, is_sleep))

        tuner_type = self.get_tuner_type(target)
        if tuner_type == self.ISDB_S:
            if is_sleep:
                write_data = (
                    # S 0x13 : 0x80 = 1000 0000
                    # jslpadc[7]=1(1)
                    # S 0x15 : 0x00 = 0000 0000
                    # tetim[4:0]=0(0000)
                    # S 0x17 : 0xff = 1111 1111
                    # watim[7:0]!=0
                    (target, 0x13, 0x80),
                    (target, 0x15, 0x00),
                    (target, 0x17, 0xff),
                )
            else:
                write_data = (
                    # S 0x13 : 0x00 = 0000 0000
                    # jslpadc[7]=0(0)
                    # S 0x15 : 0x00 = 0000 0000
                    # tetim[4:0]=0(0000)
                    # S 0x17 : 0x00 = 0000 0000
                    # watim[7:0]=0(0000 0000)
                    (target, 0x13, 0x00),
                    (target, 0x15, 0x00),
                    (target, 0x17, 0x00),
                )
        else:
            if is_sleep:
                write_data = (
                    # T 0x03 : 0xf0 = 1111 0000
                    # slpadc[7]=1(1), slptim[6-4]!=0(111), wuptim[3-0]=0(0000)
                    (target, 0x03, 0xf0),
                )
            else:
                write_data = (
                    # T 0x03 : 0x0f0 = 0000 0000
                    # slpadc[7]=0(0), slptim[6-4]=0(000), wuptim[3-0]=0(0000)
                    (target, 0x03, 0x00),
                )
        self.write_data_demodulator(write_data)

    def set_init_demodulator(self, target: int):
        Logger.trace_function('target={}'.format(target))

        self.set_system_reset_demodulator(target)
        tuner_type = self.get_tuner_type(target)
        if tuner_type == self.ISDB_S:
            write_data = (
                (target, 0x15, 0x00),
                (target, 0x1d, 0x00),
            )
        else:
            write_data = (
                (target, 0xb0, 0xa0),
                (target, 0xb2, 0x3d),
                (target, 0xb3, 0x25),
                (target, 0xb4, 0x8b),
                (target, 0xb5, 0x4b),
                (target, 0xb6, 0x3f),
                (target, 0xb7, 0xff),
                (target, 0xb8, 0xc0),
            )
        self.write_data_demodulator(write_data)

    def set_output_pin_demodulator(self, target: int):
        Logger.trace_function('target={}'.format(target))

        tuner_type = self.get_tuner_type(target)
        if tuner_type == self.ISDB_S:
            target_t = self.get_pair_target(target)
            self.read_demodulator(target_t, 0x0f)
            self.read_demodulator(target, 0x07)
            write_data = (
                # T 0x0e : 0x11 = 0001 0001
                # ?
                (target_t, 0x0e, 0x11),

                # T 0x0f : 0x70 = 0111 0000
                # pinsld[7:6]=1(01), pinslc[5:4]=3(11)
                # pinslb[3:2]=0(00), pinsla[1:0]=0(00)
                # pinslc=3 : output PSK to C
                (target_t, 0x0f, 0x70),

                # S 0x07 : 0x77 = 0111 0111
                # jtsld[6]=1(1), jtslc[4]=1(1)
                # jtslb[2]=1(1), jtsla[0]=1(1)
                # jtslc=1 : output Parallel TS to C ?
                (target, 0x07, 0x77),

                # S 0x08 : 0x10 = 0001 0000
                # ?
                (target, 0x08, 0x10),

                # S 0x04 = 0000 0100
                # chclkp[1]=0(0) ?
                (target, 0x04, 0x02),

                # S 0x8e : 0x02 = 0000 0010
                # nuval[1]=1(1)
                (target, 0x8e, 0x02),

                # T 0x1f : 0x20 : 0010 0000
                # pbvaloen[5:4]=2(10)
                (target_t, 0x1f, 0x20),
            )
        else:
            write_data = (
                # T 0x0e : 0x77
                # ?
                (target, 0x0e, 0x77),

                # T 0x0f : 0x10 = 0001 0000
                # pinsld[7:6]=0(00), pinslc[5:4]=1(01)
                # pinslb[3:2]=0(00), pinsla[1:0]=0(00)
                # pinslc=1 : output OFDM Serial to C
                (target, 0x0f, 0x10),

                # T 0x71 : 0x20 : 0010 0000
                # palonff[5]=1
                (target, 0x71, 0x20),

                # T 0x76 : 0x0c = 0000 1100
                # nuval[3]=1(1) anuval[2]=1(1)
                (target, 0x76, 0x0c),

                # T 0x1f : 0x30 = 0011 0000
                # pbvaloen[5:4]=3(11)
                (target, 0x1f, 0x30),
            )
        self.write_data_demodulator(write_data)

    def set_output_signal_demodulator(self, target: int, is_output: bool):
        Logger.trace_function('target={} output={}'.format(target, is_output))

        tuner_type = self.get_tuner_type(target)
        if tuner_type == self.ISDB_S:
            if is_output:
                write_data = (
                    (target, 0x1c, 0x00),
                    (target, 0x1f, 0x00),
                )
            else:
                write_data = (
                    (target, 0x1c, 0x80),
                    (target, 0x1f, 0x22),
                )
            self.write_data_demodulator(write_data)
        else:
            if is_output:
                self.write_demodulator(target, 0x1d, 0x00)
            else:
                self.write_demodulator(target, 0x1d, 0xa8)

    def set_sleep_tuner(self, target: int, is_sleep: bool):
        Logger.trace_function('target={} sleep={}'.format(target, is_sleep))

        tuner_type = self.get_tuner_type(target)
        if tuner_type == self.ISDB_S:
            write_data = self.get_sleep_register_tuner_s()
            if is_sleep:
                write_data[0x03] = 0x20
                self.write_tuner(target, 0x00, write_data)
            else:
                pass
        else:
            pass

    def open_usb_bridge(self):
        Logger.trace_function()

        self.get_chip_id()
        self.get_firmware_version()
        if not self.is_load_firmware():
            self.load_firmware()
        self.init_usb_bridge()
        self.set_sleep_usb_bridge(False)

    def close_usb_bridge(self):
        Logger.trace_function()

        self.set_sleep_usb_bridge(True)

    def open_demodulator(self):
        Logger.trace_function()

        for target in self.get_targets():
            self.set_sleep_demodulator(target, False)
            self.set_init_demodulator(target)
            self.set_output_signal_demodulator(target, False)
            self.set_sleep_demodulator(target, True)

    def close_demodulator(self):
        Logger.trace_function()

        for target in self.get_targets():
            self.set_output_signal_demodulator(target, False)
            self.set_sleep_demodulator(target, True)

    def open_tuner(self):
        Logger.trace_function()

        for target in self.get_targets():
            tuner_type = self.get_tuner_type(target)
            if tuner_type == self.ISDB_S:
                read_data = self.read_tuner(target, 0x00, 4, is_reverse=False)
                Logger.debug('tuner_s id reg=%x:%x', 0x00, read_data[0x00])
                read_data[3] = self.bit_reverse(read_data[3])
                Logger.debug('tuner_s id reg=%x:%x', 0x03, read_data[0x03])
            else:
                read_data = self.read_tuner(target, 0x00, is_reverse=False)
                Logger.debug('tuner_t id reg=%x:%x', 0x00, read_data)
            self.set_sleep_tuner(target, True)

    def close_tuner(self):
        Logger.trace_function()

        for target in self.get_targets():
            self.set_sleep_tuner(target, True)

    def get_initial_register_tuner_s(self, address=None):
        registers = [
            0x40, 0x1d, 0x20, 0x10,  # 0-3
            0x41, 0x50, 0xed, 0x25,  # 4-7
            0x07, 0x58, 0x39, 0x64,  # 8-11
            0x38, 0xf7, 0x90, 0x35,  # 12-15
        ]

        if address is None:
            return registers
        else:
            return registers[address]

    def get_sleep_register_tuner_s(self, address=None):
        registers = [
            0xff, 0x5c, 0x88, 0x30,
            0x41, 0xc8, 0xed, 0x25,
            0x47, 0xfc, 0x48, 0xa2,
            0x08, 0x0f, 0xf3, 0x59,
        ]

        if address is None:
            return registers
        else:
            return registers[address]

    def get_register_tuner_s(self, target: int, frequency: int):
        data = []
        min = 2350000
        max = min * 2
        div = 2
        a = 0
        while True:
            q = frequency * div
            if q >= min and q <= max:
                if div == 2:
                    a = 1
                    break
                elif div == 4:
                    a = 0
                    break
                elif div == 8:
                    a = 2
                    break
                elif div == 16:
                    a = 3
                    break
            div *= 2
            if div > 16:
                raise RuntimeError(
                    'invalid ISDB-S frequency={} div={}'.format(
                        frequency, div
                    )
                )

        reg4 = self.get_initial_register_tuner_s(0x04)
        reg4 &= 0xfe
        reg4 |= (a & 1)
        data.append((target, 0x04, reg4))

        b = frequency * div
        c = (b // 2) // 24000
        d = c & 0xff
        e = (d * 17536 + b) & 0xffff

        if e < 375:
            e = 0
        elif e > 47625:
            e = 0
            d += 1
        elif e > 23812 and e < 24000:
            e = 23812
        elif e > 24000 and e < 24187:
            e = 24187

        reg5 = self.get_initial_register_tuner_s(0x05)
        f = ((d - 13) // 4) & 0xff
        reg5 = (f + ((d - (f * 4) - 13) << 6)) & 0xff
        data.append((target, 0x05, reg5))

        if not e:
            reg4 |= 0x02
            data.append((target, 0x04, reg4))

        g = 2
        h = 0
        while e > 1:
            s = (24000 * 2) // g
            if e > s:
                h += (32768 // (g // 2))
                e -= s
                if g >= 32768:
                    break
            g *= 2

        reg7 = ((h >> 8) & 0xff)
        reg6 = (h & 0xff)
        data.append((target, 0x07, reg7))
        data.append((target, 0x06, reg6))

        symbol_rate = 28860
        rolloff = 4
        b = 0
        f = 0
        c = (
            (50000, 0, 0),
            (73000, 0, 1),
            (96000, 1, 0),
            (104000, 1, 1),
            (116000, 2, 0),
            (126000, 2, 1),
            (134000, 3, 0),
            (146000, 3, 1),
            (158000, 4, 0),
            (170000, 4, 1),
            (178000, 5, 0),
            (190000, 5, 1),
            (202000, 6, 0),
            (212000, 6, 1),
            (218000, 7, 0),
            (234000, 7, 1),
            (244000, 9, 1),
            (246000, 10, 0),
            (262000, 10, 1),
            (266000, 11, 0),
            (282000, 11, 1),
            (298000, 12, 1),
            (318000, 13, 1),
            (340000, 14, 1),
            (358000, 15, 1),
            (379999, 16, 1),
        )

        reg2 = self.get_initial_register_tuner_s(0x02)
        reg8 = self.get_initial_register_tuner_s(0x08)
        rega = self.get_initial_register_tuner_s(0x0a)
        if frequency < 1600000 or frequency > 1950000:
            reg2 &= 0xbf
            reg8 &= 0x7f
            if frequency >= 1950000:
                rega = 0x38
        else:
            reg2 |= 0x40
            reg8 |= 0x80
        data.append((target, 0x0a, rega))
        data.append((target, 0x02, reg2))
        data.append((target, 0x08, reg8))

        rege = self.get_initial_register_tuner_s(0x0e)
        rege &= 0xf3
        if frequency >= 2000000:
            rege |= 0x08
        data.append((target, 0x0e, rege))

        a = (symbol_rate * (0x73 + (rolloff * 5))) // 10
        if not a:
            raise RuntimeError(
                'invalid ISDB-S freqency = {} a = {}'.format(
                    frequency, a
                )
            )
        if a >= 380000:
            a -= 380000
            if a % 17400:
                b += 1
            a //= 17400
            b += (a & 0xff) + 0x10
            f = 1
        else:
            for ci in c:
                if a <= ci[0]:
                    b = ci[1]
                    f = ci[2]
                    break
        regf = (b << 2) | f
        data.append((target, 0x0f, regf))

        return data

    def set_frequency_s(self, target: int, frequency: int):
        Logger.trace_function(
            'target={} freq={}'.format(target, frequency)
        )

        write_data = self.get_initial_register_tuner_s()
        self.write_tuner(target, 0x00, write_data)
        time.sleep(0.01)
        write_data = self.get_register_tuner_s(target, frequency)
        self.write_data_tuner(write_data)

    def lock_tuner_s(self, target: int, max_count: int, wait: float=0.1):
        Logger.trace_function('target={}'.format(target))

        is_lock = False
        for _ in range(max_count):
            value = self.read_tuner(target, 0x02)
            Logger.debug('tuner lock reg=%x:%x', 0x02, value)
            if self.bit_flag(value, 7):
                is_lock = True
                break
            time.sleep(wait)
        if not is_lock:
            raise RuntimeError('fail to lock tuner_s')

    def lock_tmcc_s(self, target: int, max_count, wait=0.1):
        Logger.trace_function('target={}'.format(target))

        is_lock = False
        for _ in range(max_count):
            value = self.read_demodulator(target, 0xc3)
            Logger.debug('lock tmcc_s reg=%x:%x', 0xc3, value)
            if self.bit_flag(value, 4, False):  # tmcerr = 0
                is_lock = True
                break
            time.sleep(wait)
        if not is_lock:
            raise RuntimeError('fail to lock tmcc demodulator_s')

    def lock_rlock_s(self, target: int, max_count: int, wait: float=0.1):
        Logger.trace_function('target={}'.format(target))

        is_lock = False
        for _ in range(max_count):
            value = self.read_demodulator(target, 0xc5)
            if self.bit_flag(value, 1):  # rlockh = 1
                is_lock = True
                break
            elif self.bit_flag(value, 0):  # rlockl = 1
                is_lock = True
                break
            time.sleep(wait)
        if not is_lock:
            raise RuntimeError(
                'fail to lock rlockh or rlockl demodulator_s'
            )

    def lock_ts_id_s(self, target: int, ts_id: int, max_count: int, wait: float=0.1):
        Logger.trace_function('target={} tsid={:x}'.format(target, ts_id))

        is_lock = False
        for _ in range(max_count):
            value = self.get_ts_id_demodulator_s(target)
            if ts_id == value:
                is_lock = True
                break
            time.sleep(wait)
        if not is_lock:
            raise RuntimeError(
                'fail to lock ts id {:x}'.format(ts_id)
            )

    def set_reset_demodulator(self, target: int):
        Logger.trace_function('target={}'.format(target))

        tuner_type = self.get_tuner_type(target)
        if tuner_type == self.ISDB_S:
            # pskmsrst=1
            self.write_demodulator(target, 0x03, 0x01)
        else:
            # imsrst=1
            self.write_demodulator(target, 0x01, 0x40)

    def set_agc_demodulator(self, target: int, is_on: bool):
        Logger.trace_function('target={} on={}'.format(target, is_on))

        tuner_type = self.get_tuner_type(target)
        if tuner_type == self.ISDB_S:
            if is_on:
                write_data = (
                    # S 0x0a : 0xff = 1111 1111
                    # aglmax=0xff
                    (target, 0x0a, 0xff),

                    # S 0x10 : 0xb2 1011 0010
                    # ?=2(10),aagcdv=6(110),?=0,amglvl=2(10)
                    (target, 0x10, 0xb2),

                    # S 0x11 : 0x00 0000 0000
                    # amglvl=0(0000 0000)
                    (target, 0x11, 0x00),
                )
            else:
                write_data = (
                    # S 0x0a : 0x00 = 0000 0000
                    # aglmax=0
                    (target, 0x0a, 0x00),

                    # S 0x10 : 0xb0 = 1011 0000
                    # ?=2(10),aagcdv=6(110),?=0(0),amglvl=0(00)
                    (target, 0x10, 0xb0),

                    # S 0x11 : 0x00 0000 0010
                    # amglvl=2(0000 0010)
                    (target, 0x11, 0x02),
                )
        else:
            if is_on:
                write_data = (
                    # T 0x20 : 0x00 = 0000 0000
                    # delayp=0(0000 0000)
                    (target, 0x20, 0x00),

                    # T 0x23 0x4d = 0100 1101
                    # ifagcg1=2(010),ifagcg2=3(011)
                    # ifagc_inv=0(0),ifmgcon=1(1)
                    (target, 0x23, 0x4d),

                    # T 0x25 0x00= 0000 0000
                    # ifmgc=0(0000 0000)
                    (target, 0x25, 0x00),
                )
            else:
                write_data = (
                    # T 0x20 : 0x00 = 0000 0000
                    # delayp=0(0000 0000)
                    (target, 0x20, 0x00),

                    # T 0x23 : 0x4c = 0100 1100
                    # ifagcg1=0x02(010),ifagcg2=3(011)
                    # ifagc_inv=0(0),ifmgcon=0(0)
                    (target, 0x23, 0x4c),

                    # T 0x25 0x00= 0000 0000
                    # ifmgc=0(0000 0000)
                    (target, 0x25, 0x00),
                )
        self.write_data_demodulator(write_data)
        self.set_reset_demodulator(target)

    def set_ts_id_demodulator_s(self, target: int, ts_id: int):
        Logger.trace_function('target={} tsid={:x}'.format(target, ts_id))

        # S 0x8f,0x90 : iits
        write_data = (
            (target, 0x8f, (ts_id >> 8) & 0xff),
            (target, 0x90, ts_id & 0xff),
        )
        self.write_data_demodulator(write_data)

    def get_ts_id_demodulator_s(self, target: int) -> int:
        Logger.trace_function('target={}'.format(target))

        # S 0xe6,0xe7 : tsido
        read_data = self.read_demodulator(target, 0xe6, read_length=2)
        ts_id = int.from_bytes(read_data, 'big')
        Logger.debug('ts id = %x', ts_id)
        return ts_id

    def get_tmcc_ts_slot_demodulator_s(self, target: int):
        Logger.trace_function('target={}'.format(target))

        # S 0xc6 : acnt[5:0]
        read_data = self.read_demodulator(target, 0xc6)
        acnt = (read_data & 0xfc) >> 2

        Logger.debug('acnt = {}'.format(acnt))
        return acnt

    def get_tmcc_ts_ids_demodulator_s(self, target: int):
        Logger.trace_function('target={}'.format(target))

        # S 0xce : tsid0-tsid8
        ts_ids = []
        for i in range(0, 8):
            address = 0xce + i * 2
            val = self.read_demodulator(target, address, read_length=2)
            ts_ids.append(int.from_bytes(val, 'big'))

        Logger.debug('ts ids = {}'.format(ts_ids))
        return ts_ids

    def open(self):
        Logger.trace_function()

        self.open_usb_device()
        self.open_usb_bridge()
        self.open_demodulator()
        self.open_tuner()

        self._is_init_device = True

    def close(self):
        Logger.trace_function()

        if not self._is_init_device:
            return
        self.close_tuner()
        self.close_demodulator()
        self.close_usb_bridge()
        self.close_usb_device()

        self._is_init_device = False

    def get_cnr(self, target) -> float:
        Logger.trace_function('target={}'.format(target))

        if not self.is_open_tuner(target):
            return 0.0
        tuner_type = self.get_tuner_type(target)
        if tuner_type == self.ISDB_S:
            read_data = self.read_demodulator(target, 0xbc, read_length=2)
            cnmc = int.from_bytes(read_data, 'big')
            if cnmc < 3000:
                cnmc = 3000
            pval = math.sqrt(cnmc - 3000) / 64.0
            cnr = -1.6346 * pval**5 + 14.341 * pval**4 - 50.259 * pval**3 + \
                88.977 * pval**2 - 89.595 * pval + 58.857
        else:
            read_data = self.read_demodulator(target, 0x8b, read_length=3)
            cndat = int.from_bytes(read_data, 'big')
            if cndat <= 0:
                return 0.0
            pval = 10 * math.log10(5505024.0 / cndat)
            cnr = 0.000024 * pval**4 - 0.0016 * pval**3 + 0.0398 * pval**2 + \
                0.5491 * pval + 3.0965
        Logger.debug('cnr = %f', cnr)
        return cnr

    def get_ts_ids(self, target: int, frequency: int) -> list:
        Logger.trace_function('target={} freq={}'.format(target, frequency))

        self.set_sleep_demodulator(target, False)
        self.set_sleep_tuner(target, False)
        self.set_agc_demodulator(target, False)
        self.set_frequency_s(target, frequency)
        self.lock_tuner_s(target, self.MAX_COUNT_LOCK_TUNER_S)
        self.set_agc_demodulator(target, True)
        self.lock_tmcc_s(target, self.MAX_COUNT_LOCK_DEMODULATOR_S)
        ts_ids = self.get_tmcc_ts_ids_demodulator_s(target)
        Logger.info('TSID {}'.format(ts_ids))
        self.set_sleep_demodulator(target, True)
        self.set_sleep_tuner(target, True)

        return ts_ids


class StopEvent:

    def __init__(self):
        self._event_stop: threading.Event = threading.Event()
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        if platform.system() == 'Linux':
            signal.signal(signal.SIGPIPE, self.signal_handler)
            signal.signal(signal.SIGQUIT, self.signal_handler)

    def signal_handler(self, signum, stack):
        self._event_stop.set()

    def clear(self):
        self._event_stop.clear()

    def wait(self, seconds):
        self._event_stop.wait(timeout=seconds)

    def is_set(self):
        return self._event_stop.is_set()

def main():
    config = Config('scan tsid command', isdb_s=True, isdb_t=False)
    Logger.init(__name__, config.get('log_level'))

    # BS
    results = []
    for i in range(0, 12):
        tpnum = 2 * i + 1
        freq = 1049480 + 38360 * i
        results.append(
            {
                'transponder': 'BS{}'.format(tpnum),
                'number': tpnum,
                'frequency_idx': i,
                'frequency_khz': freq + 10678000,
                'frequency_if_khz': freq,
                'transport_stream_id': [],
                'has_lock': False,
            }
        )
    # CS
    for i in range(0, 12):
        tpnum = 2 * i + 2
        freq = 1613000 + 40000 * i
        results.append(
            {
                'transponder': 'ND{}'.format(tpnum),
                'number': tpnum,
                'frequency_idx': i + 12,
                'frequency_khz': freq + 10678000,
                'frequency_if_khz': freq,
                'transport_stream_id': [],
                'has_lock': False,
            }
        )

    event = StopEvent()
    with TunerDevice(config) as device:
        device.open()
        for r in results:
            if event.is_set():
                break
            Logger.info('{} {}kHz'.format(r['transponder'], r['frequency_if_khz']))
            try:
                r['transport_stream_id'] = device.get_ts_ids(device.ISDB_S0, r['frequency_if_khz'])
                r['has_lock'] = True
            except Exception as e:
                Logger.info(e)

    json.dump(results, config.write(), indent=4)

if __name__ == '__main__':
    try:
        main()
    except Exception as err:
        print(traceback.format_exc(), file=sys.stderr)
