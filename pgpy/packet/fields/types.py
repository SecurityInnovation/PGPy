""" packetfield.py
"""

import abc


class PacketField(object, metaclass=abc.ABCMeta):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def parse(self, packet):  # pragma: no cover
        raise NotImplementedError()

    @abc.abstractmethod
    def __bytes__(self):  # pragma: no cover
        raise NotImplementedError()

    @abc.abstractmethod
    def __pgpdump__(self):  # pragma: no cover
        raise NotImplementedError
