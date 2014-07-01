""" userattribute.py
"""
import struct

from .types import SubPacket
from ..types import PFIntEnum
from ...util import bytes_to_int
from ...util import int_to_bytes


class UASubPacket(SubPacket):
    class Type(SubPacket.Type):
        Image = 0x01

        @property
        def subclass(self):
            classes = {'Image': Image}

            if classes[self.name] is not None:
                return classes[self.name]

            raise NotImplementedError(self.name)  # pragma: no cover

        def __str__(self):
            return self.subclass.name


class Image(UASubPacket):
    """
    5.12.1. The Image Attribute Subpacket

    The Image Attribute subpacket is used to encode an image, presumably
    (but not required to be) that of the key owner.

    The Image Attribute subpacket begins with an image header.  The first
    two octets of the image header contain the length of the image
    header.  Note that unlike other multi-octet numerical values in this
    document, due to a historical accident this value is encoded as a
    little-endian number.  The image header length is followed by a
    single octet for the image header version.  The only currently
    defined version of the image header is 1, which is a 16-octet image
    header.  The first three octets of a version 1 image header are thus
    0x10, 0x00, 0x01.

    The fourth octet of a version 1 image header designates the encoding
    format of the image.  The only currently defined encoding format is
    the value 1 to indicate JPEG.  Image format types 100 through 110 are
    reserved for private or experimental use.  The rest of the version 1
    image header is made up of 12 reserved octets, all of which MUST be
    set to 0.

    The rest of the image subpacket contains the image itself.  As the
    only currently defined image type is JPEG, the image is encoded in
    the JPEG File Interchange Format (JFIF), a standard file format for
    JPEG images [JFIF].

    An implementation MAY try to determine the type of an image by
    examination of the image data if it is unable to handle a particular
    version of the image header or if a specified encoding format value
    is not recognized.
    """
    class Version(PFIntEnum):
        v1 = 0x01

    class Encoding(PFIntEnum):
        JPEG = 0x01

    name = 'image attribute'

    def __init__(self, packet):
        self.version = Image.Version.v1
        self.encoding = Image.Encoding.JPEG

        super(Image, self).__init__(packet)

    def parse(self, packet):
        hlen = struct.unpack('<h', packet[:2])[0]
        self.version = Image.Version(bytes_to_int(packet[2:3]))
        self.encoding = Image.Encoding(bytes_to_int(packet[3:4]))
        pos = hlen
        self.payload = packet[pos:]

    def __bytes__(self):
        _bytes = super(Image, self).__bytes__()

        # there is only v1
        if self.version == Image.Version.v1:
            # v1 image header length is always 16 bytes,
            # and stored little-endian due to an 'historical accident'
            _bytes += struct.pack('<h', 16)
            _bytes += int_to_bytes(self.version)
            _bytes += int_to_bytes(self.encoding)
            _bytes += b'\x00' * 12

        _bytes += self.payload
        return _bytes
