"""shared test stuff. all passwords here are fake"""

import os
import tempfile
import unittest
from unittest import mock

from pwmanager import crypto

MASTER_PASSWORD = "test-master-password"
OTHER_MASTER_PASSWORD = "other-master-password"
ENTRY_PASSWORD = "dummy-pw-123"

real_new_key_settings = crypto.new_key_settings


def fast_key_settings():
    # small n so the tests dont take forever
    return real_new_key_settings(n=2 ** 14)


class TempDirTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.path = os.path.join(self.temp_dir.name, "test.vault")
        patcher = mock.patch.object(crypto, "new_key_settings", fast_key_settings)
        patcher.start()
        self.addCleanup(patcher.stop)
