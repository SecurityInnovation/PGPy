#!/usr/bin/env python
import asyncio
import collections
import itertools
import os
import sys
import time

from progressbar import ProgressBar, AnimatedMarker, Timer, Bar, Percentage, Widget

import pgpy
from pgpy.packet import Packet
from pgpy.types import Exportable

pubring = '/Users/magreene/paul_pubring.asc'

@asyncio.coroutine
def _dospinner(pbar):
    for i in pbar(itertools.cycle(range(100))):
        try:
            yield from asyncio.shield(asyncio.sleep(0.005))

        except asyncio.CancelledError:
            print("")
            break

pbar1 = ProgressBar(widgets=["Reading {} ({:,} bytes): ".format(pubring, os.path.getsize(pubring)), AnimatedMarker()])
pbar2 = ProgressBar(widgets=["Unarmoring data: ", AnimatedMarker()])

@asyncio.coroutine
def _load_pubring(future):
    with open(pubring, 'r') as ppr:
        a = yield from asyncio.get_event_loop().run_in_executor(None, ppr.read)
        future.set_result(a)

@asyncio.coroutine
def _unarmor(a, future):
    b = yield from asyncio.get_event_loop().run_in_executor(None, pgpy.types.Exportable.ascii_unarmor, a)
    future.set_result(b)

loop = asyncio.get_event_loop()

a = asyncio.Future()
b = asyncio.Future()

prog = asyncio.Task(_dospinner(pbar1))
asyncio.Task(_load_pubring(a))
loop.run_until_complete(a)
_a = a.result()
prog.cancel()

prog = asyncio.Task(_dospinner(pbar2))
asyncio.Task(_unarmor(_a, b))
loop.run_until_complete(b)
_b = b.result()['body']
prog.cancel()
loop.stop()
print("")

packets = []
_mv = len(_b)

class PacketCounter(Widget):
    def __init__(self, pktlist, format='{:,} pkts'):
        self.pktlist = pktlist
        self.format = format

    def update(self, pbar):
        return self.format.format(len(self.pktlist))

pb3w = [PacketCounter(packets), '|', Timer("%s"), '|', Percentage(), Bar()]

pbar3 = ProgressBar(maxval=_mv, widgets=pb3w).start()
while len(_b) > 0:
    packets.append(Packet(_b))
    pbar3.update(_mv - len(_b))
pbar3.finish()

print("\n\n")
print('Parsed Packet Stats\n')

pcnts = collections.Counter(['{cls:s} v{v:d}'.format(cls=c.__class__.__name__, v=c.version) if hasattr(c, 'version') else c.__class__.__name__ 
                             for c in packets if not isinstance(c, pgpy.packet.Opaque)] +
                            ['Opaque [{:02d}]'.format(c.header.tag) for c in packets if isinstance(c, pgpy.packet.Opaque)])

ml = max(5, max([len(s) for s in pcnts.keys()]))
mcl = max(5, max([len("{:,}".format(c)) for c in pcnts.values()]))

print('Class{0: <{pad1}} Count\n' \
      '====={0:=<{pad1}} ====={0:=<{pad2}}'.format('', pad1=(ml - 5), pad2=(mcl - 5)))

for pc, cnt in sorted(pcnts.items(), key=lambda x: x[1], reverse=True):
    print('{cls:{pad1}} {count: <{pad2},}'.format(pad1=ml, pad2=mcl, cls=pc, count=cnt))

print("")
