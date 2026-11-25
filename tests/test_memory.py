import os
import subprocess
import sys
import unittest

from pwmanager import secure_input, secure_memory, vault
from tests.helpers import ENTRY_PASSWORD, MASTER_PASSWORD, TempDirTestCase


class WipeTests(unittest.TestCase):
    def test_wipe_bytearray(self):
        buffer = bytearray(os.urandom(32))
        secure_memory.wipe(buffer)
        self.assertEqual(buffer, bytearray(32))
        self.assertEqual(len(buffer), 32)

    def test_wipe_bytes_in_place(self):
        data = os.urandom(32)  # fresh object, not a shared constant
        secure_memory.wipe_bytes(data)
        self.assertEqual(data, bytes(32))

    def test_wipe_bytes_skips_shared_objects(self):
        # empty and 1 byte objects are shared in cpython, wiping them would break things
        secure_memory.wipe_bytes(b"")
        one = bytes([65])
        secure_memory.wipe_bytes(one)
        self.assertEqual(bytes([65]), b"A")

    def test_wipe_ignores_other_types(self):
        secure_memory.wipe("not a buffer")
        secure_memory.wipe_bytes("not bytes")
        secure_memory.wipe_bytes(bytearray(b"ab"))


class SessionMemoryTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        vault.create(self.path)
        vault.register(self.path, "alice", MASTER_PASSWORD)

    def test_key_is_wiped_when_session_closes(self):
        with vault.login(self.path, "alice", MASTER_PASSWORD) as session:
            session.add_entry("example.com", "alice", ENTRY_PASSWORD)
            key = session.key
            self.assertNotEqual(key, bytearray(len(key)))
        self.assertEqual(key, bytearray(len(key)))
        self.assertEqual(session.entries, {})

    def test_key_is_wiped_when_an_error_happens(self):
        try:
            with vault.login(self.path, "alice", MASTER_PASSWORD) as session:
                key = session.key
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        self.assertEqual(key, bytearray(len(key)))

    def test_old_key_wiped_after_master_password_change(self):
        with vault.login(self.path, "alice", MASTER_PASSWORD) as session:
            old_key = session.key
            session.change_master_password("another-master-password")
            self.assertEqual(old_key, bytearray(len(old_key)))
            self.assertIsNot(session.key, old_key)


class SecretInputTests(unittest.TestCase):
    def read_through_pipe(self, data):
        r, w = os.pipe()
        os.write(w, data)
        os.close(w)
        try:
            return secure_input._read_line(r)
        finally:
            os.close(r)

    def test_reads_into_bytearray(self):
        result = self.read_through_pipe(b"dummy-secret\nnext line")
        self.assertIsInstance(result, bytearray)
        self.assertEqual(result, bytearray(b"dummy-secret"))

    def test_stops_at_end_of_input(self):
        self.assertEqual(self.read_through_pipe(b"abc"), bytearray(b"abc"))

    def test_very_long_input_is_cut(self):
        result = self.read_through_pipe(b"x" * 5000 + b"\n")
        self.assertEqual(len(result), secure_input.MAX_INPUT)


@unittest.skipUnless(sys.platform.startswith("linux"), "linux only")
class ProcessHardeningTests(unittest.TestCase):
    def test_core_dumps_disabled(self):
        # in a separate process so it doesnt depend on what other tests did
        code = ("import resource; from pwmanager import secure_memory; "
                "secure_memory.harden_process(); "
                "print(resource.getrlimit(resource.RLIMIT_CORE), secure_memory.is_dumpable())")
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.assertEqual(result.stdout.strip(), "(0, 0) False")


if __name__ == "__main__":
    unittest.main()
