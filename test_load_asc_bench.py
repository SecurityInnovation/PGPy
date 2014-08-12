#!/usr/bin/env python
import asyncio
import bisect
import collections
import itertools
import os
import sys

from progressbar import ProgressBar, AnimatedMarker, Timer, Bar, Percentage, Widget

import pgpy
from pgpy.packet import Packet
from pgpy.types import Exportable


ascfiles = [ os.path.abspath(os.path.expanduser(f)) for f in sys.argv[1:] if os.path.exists(os.path.abspath(os.path.expanduser(f))) ]

if len(ascfiles) == 0:
    sys.stderr.write("Please specify one or more ASCII-armored files to load\n")
    sys.exit(-1)

for a in [ os.path.abspath(os.path.expanduser(a)) for a in sys.argv[1:] if a not in ascfiles ]:
    sys.stderr.write("Error: {} does not exist\n".write())

class Mebibyte(int):
    iec = {1: 'B',
           1024: 'KiB',
           1024**2: 'MiB',
           1024**3: 'GiB',
           1024**4: 'TiB',
           1024**5: 'PiB',
           1024**6: 'EiB',
           1024**7: 'ZiB',
           1024**8: 'YiB'}
    iecl = [1, 1024, 1024**2, 1024**3, 1024**4, 1024**5, 1024**6, 1024**7, 1024**8]

    # custom format class for human readable IEC byte formatting
    def __format__(self, spec):
        # automatically format based on size

        iiec = max(0, min(bisect.bisect_right(self.iecl, int(self)), len(self.iecl)))
        ieck = self.iecl[iiec - 1]
        return '{:,.2f} {:s}'.format(int(self) / ieck, self.iec[ieck])


@asyncio.coroutine
def _dospinner(pbar):
    for i in pbar(itertools.cycle(range(100))):
        try:
            yield from asyncio.shield(asyncio.sleep(0.005))

        except asyncio.CancelledError:
            print("")
            break

@asyncio.coroutine
def _load_pubring(ascfile, future):
    with open(ascfile, 'r') as ppr:
        a = yield from asyncio.get_event_loop().run_in_executor(None, ppr.read)
        future.set_result(a)

@asyncio.coroutine
def _unarmor(a, future):
    b = yield from asyncio.get_event_loop().run_in_executor(None, pgpy.types.Exportable.ascii_unarmor, a)
    future.set_result(b)

_b = bytearray()


loop = asyncio.get_event_loop()
for ascfile in ascfiles:
    ascfile = os.path.abspath(ascfile)
    if not os.path.isfile(ascfile):
        sys.stderr.write('Error: {} does not exist'.format(ascfile))
        continue

    load_bar = ProgressBar(widgets=["Reading {} ({}): ".format(ascfile, Mebibyte(os.path.getsize(ascfile))), AnimatedMarker()])
    unarmor_bar = ProgressBar(widgets=["Unarmoring data: ", AnimatedMarker()])


    a = asyncio.Future()
    b = asyncio.Future()

    lbp = asyncio.Task(_dospinner(load_bar))
    asyncio.Task(_load_pubring(ascfile, a))
    loop.run_until_complete(a)
    _a = a.result()
    lbp.cancel()

    uap = asyncio.Task(_dospinner(unarmor_bar))
    asyncio.Task(_unarmor(_a, b))
    loop.run_until_complete(b)
    _b += b.result()['body']
    uap.cancel()

loop.stop()
print("\n")

packets = []
_mv = len(_b)


class BetterCounter(Widget):
    def __init__(self, pktlist, iec=False, format='{:,}'):
        self.list = pktlist
        self.iec = iec
        self.format = format

    def update(self, pbar):
        if self.iec:
            return self.format.format(Mebibyte(len(self.list)))

        return self.format.format(len(self.list))


pb3w = [BetterCounter(packets, False, '{:,} pkts'), '|', BetterCounter(_b, True, '{:,} rem.'), '|', Timer("%s"), '|', Percentage(), Bar()]

pbar3 = ProgressBar(maxval=_mv, widgets=pb3w).start()
while len(_b) > 0:
    olen = len(_b)
    pkt = Packet(_b)
    # if len(packets) == 10132:
    #     a=0
    # try:
    #     pkt = Packet(_b)
    #
    # except:
    #     print("\n\tSomething went wrong!")
    #     print("\tBad packet followed packet #{:,d}".format(len(packets)))
    #     print("\tLast packet was: {:s} (tag {:d}) ({:,d} bytes)".format(packets[-1].__class__.__name__, packets[-1].header.tag, packets[-1].header.length))
    #     print("\t{:,d} bytes left unparsed".format(len(_b)))
    #     print("\tFailed packet consumed {:,d} bytes".format(olen - len(_b)))
    #     raise
    #
    # if (olen - len(_b)) != len(pkt.header) + pkt.header.length:
    #     print("Incorrect number of bytes consumed. Got: {:,}. Expected: {:,}".format((olen - len(_b)), (len(pkt.header) + pkt.header.length)))
    #     print("Bad packet was: {cls:s}, {id:d}, {ver:s}".format(cls=pkt.__class__.__name__, id=pkt.header.typeid, ver=str(pkt.header.version) if hasattr(pkt.header, 'version') else ''))
    #     print("loaded: " + str(len(packets)))
    packets.append(pkt)
    pbar3.update(_mv - len(_b))
pbar3.finish()

print("\n\n")
print('Parsed Packet Stats\n')

pcnts = collections.Counter(['{cls:s} v{v:d}'.format(cls=c.__class__.__name__, v=c.version) if hasattr(c, 'version') else c.__class__.__name__ 
                             for c in packets if not isinstance(c, pgpy.packet.Opaque)] +
                            ['Opaque [{:02d}]{:s}'.format(c.header.tag, '[v{:d}]'.format(c.header.version) if hasattr(c.header, 'version') else '') for c in packets if isinstance(c, pgpy.packet.Opaque)])

ml = max(5, max([len(s) for s in pcnts.keys()]))
mcl = max(5, max([len("{:,}".format(c)) for c in pcnts.values()]))

print('Class{0: <{pad1}} Count\n' \
      '====={0:=<{pad1}} ====={0:=<{pad2}}'.format('', pad1=(ml - 5), pad2=(mcl - 5)))

for pc, cnt in sorted(pcnts.items(), key=lambda x: x[1], reverse=True):
    print('{cls:{pad1}} {count: <{pad2},}'.format(pad1=ml, pad2=mcl, cls=pc, count=cnt))

print("")
