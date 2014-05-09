import pytest
import os
import subprocess

def pytest_runtest_setup(item):
    from cryptography.hazmat.backends import openssl
    print("Using " + openssl.backend.openssl_version_text() + "\n")

class TestFiles(object):
    @staticmethod
    def id(file):
        f = file.split('/')[-1]

        if f[:4] == "Test":
            if f[-8:] == '.sec.key':
                return 'sec-{kalg}{encalg}-{bitlen}'.format(
                    kalg=f.split('-')[0][4:].lower(),
                    encalg='' if 'Enc' not in f else '-' + f.split('-')[1][3:].lower(),
                    bitlen=f.split('-')[-1][:4]
                )

            else:
                return '{kalg}{encalg}-{bitlen}'.format(
                    kalg=f.split('-')[0][4:].lower(),
                    encalg='' if 'Enc' not in f else '-' + f.split('-')[1][3:].lower(),
                    bitlen=f.split('-')[-1][:4]
                )

        if f[-4:] == '.key':
            return file.replace('_', '-').split('.')[0].split('/')[-1]

        if f.split('.')[0] == 'signed_message':
            return f.split('.')[1].lower()

        if f[:7] == 'Release':
            return file.split('/')[-2]

    @property
    def pubids(self):
        return [ TestFiles.id(key) for key in self.pubs ]

    @property
    def privids(self):
        return [ TestFiles.id(key) for key in self.privs ]

    @property
    def keys(self):
        return self.pubs + self.privs

    @property
    def keyids(self):
        return self.pubids + self.privids

    @property
    def enckeys(self):
        return [ key for key in self.privs if 'Enc' in key ]

    @property
    def enckeyids(self):
        return [ TestFiles.id(key) for key in self.enckeys ]

    @property
    def sigids(self):
        return [ TestFiles.id(sig) for sig in self.sigs ]

    def __init__(self):
        self.pubs = [ 'tests/testdata/pubkeys/' + k for k in os.listdir('tests/testdata/pubkeys') if k[-4:] == '.key' ]
        self.privs = [ 'tests/testdata/seckeys/' + k for k in os.listdir('tests/testdata/seckeys') if k[-4:] == '.key' ]

        self.sigs = [ 'tests/testdata/signatures/' + k for k in os.listdir('tests/testdata/signatures') if k[-4:] == '.asc' ]
        self.sigm = [ 'tests/testdata/signed_message', ] * len(self.sigs)
        self.sigs += [ 'tests/testdata/' + d + '/Release.gpg' for d in ['aa-testing', 'debian-sid', 'ubuntu-precise'] ]
        self.sigm += [ 'tests/testdata/' + d + '/Release' for d in ['aa-testing', 'debian-sid', 'ubuntu-precise']]


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