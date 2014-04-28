import pytest
import subprocess
import re
import collections

@pytest.fixture()
def pgpdump(request):
    pgpd_args = ['pgpdump', '-i', '-l', '-m', '-p', '-u', '--']

    if 'test_PGPSignature.TestPGPSignature' in str(request.cls):
        pgpd_args.append(request._funcargs['pgpsig'])

    if 'load_priv' in request._funcargs.keys():
        pgpd_args.append(request._funcargs['load_priv'])

    if 'load_pub' in request._funcargs.keys():
        pgpd_args.append(request._funcargs['load_pub'])

    if 'load_key' in request._funcargs.keys():
        if type(request._funcargs['load_key']) is str:
            pgpd_args.append(request._funcargs['load_key'])

        else:
            pgpd_args += request._funcargs['load_key']


    return subprocess.check_output(pgpd_args)