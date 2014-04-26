import pytest
import subprocess
import re
import collections

@pytest.fixture()
def pgpdump(request):
    pgpd_args = ['pgpdump', '-i', '-l', '-m', '-p', '-u', '--']

    if 'test_PGPSignature.TestPGPSignature' in str(request.cls):
        pgpd_args.append(request._funcargs['pgpsig'])

    if 'test_PGPKeys.TestPGPPublicKey' in str(request.cls):
        pgpd_args.append(request._funcargs['load_pub'])

    return subprocess.check_output(pgpd_args)