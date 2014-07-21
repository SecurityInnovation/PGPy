""" packetfield.py
"""


class PacketField(object):
    def __init__(self, packet=None):
        if packet is not None:
            self.parse(packet)

    def parse(self, packet):
        """
        :param packet: raw packet bytes
        """
        raise NotImplementedError()  # pragma: no cover

    def __bytes__(self):
        raise NotImplementedError()  # pragma: no cover
