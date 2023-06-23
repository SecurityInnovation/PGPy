# coding=utf-8
""" verify that User ID parsing aligns with expected behavior

See also https://gitlab.com/openpgp-wg/rfc4880bis/-/merge_requests/23 for more discussion
"""

from typing import Dict, Optional, Tuple

import pytest

from pgpy import PGPUID

uids: Dict[str, Tuple[Optional[str], Optional[str], Optional[str]]] = {
    'Alice Lovelace <alice@example.org>': ('Alice Lovelace', None, 'alice@example.org'),
    '<alice@example.org>': (None, None, 'alice@example.org'),
    ' <alice@example.org>': (None, None, 'alice@example.org'),
    'Alice Lovelace (j. random hacker) <alice@example.org>': ('Alice Lovelace', 'j. random hacker', 'alice@example.org'),
    'alice@example.org': (None, None, 'alice@example.org'),
    'Alice Lovelace': ('Alice Lovelace', None, None),
}
    

class TestPGP_UserIDs(object):
    @pytest.mark.parametrize('uid', uids.keys())
    def test_uid_name(self, uid: str):
        pgpuid = PGPUID.new(uid)
        assert pgpuid.name == uids[uid][0]

    @pytest.mark.parametrize('uid', uids.keys())
    def test_uid_comment(self, uid: str):
        pgpuid = PGPUID.new(uid)
        assert pgpuid.comment == uids[uid][1]

    @pytest.mark.parametrize('uid', uids.keys())
    def test_uid_email(self, uid: str):
        pgpuid = PGPUID.new(uid)
        assert pgpuid.email == uids[uid][2]
