import pytest
import subprocess


@pytest.fixture()
def pgpdump(request):
    pgpd_args = ['pgpdump', '-i', '-l', '-m', '-p', '-u', '--']

    if 'test_PGPSignature.TestPGPSignature' in str(request.cls):
        pgpd_args.append(request._funcargs['pgpsig'])

    if 'load_key' in request._funcargs.keys():
        if type(request._funcargs['load_key']) is str:
            pgpd_args.append(request._funcargs['load_key'])

        else:
            o = b''
            for f in request._funcargs['load_key']:
                o += subprocess.check_output(pgpd_args + [f])

            return o

    return subprocess.check_output(pgpd_args)