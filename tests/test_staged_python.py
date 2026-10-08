"""Real subprocess regression for checker source appearing in its own argv."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

MODULE = Path(__file__).parents[1] / 'ops/staged_python.py'
CHECKER = b'''import json,pathlib,re,sys
cmd=pathlib.Path('/proc/self/cmdline').read_bytes().replace(b'\\0',b' ')
print(json.dumps({'matched':bool(re.search(b'nix-build',cmd)),
                  'isolated':sys.flags.isolated,'no_bytecode':sys.dont_write_bytecode}))
'''


class StagedPythonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.parent = Path(self.tmp.name)
        self.parent.chmod(0o700)
        self.script = self.parent / "read 'safe'.py"
        self.script.write_bytes(CHECKER)
        self.script.chmod(0o400)
        self.digest = hashlib.sha256(CHECKER).hexdigest()
        self.factory = None
        if MODULE.is_file():
            spec = importlib.util.spec_from_file_location('staged_python', MODULE)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.factory = module.staged_python_argv

    def argv(self, **kwargs):
        if self.factory is None:
            # RED witness: the old transport passes the same checker bytes inline.
            return [sys.executable, '-I', '-B', '-c', CHECKER.decode()]
        return self.factory(sys.executable, str(self.script), self.digest,
                            owner_uid=os.getuid(), **kwargs)

    def run_argv(self, argv):
        return subprocess.run(argv, capture_output=True, timeout=3, check=False)

    def test_same_checker_bytes_stop_matching_the_checker_process_itself(self):
        inline = self.run_argv([sys.executable, '-I', '-B', '-c', CHECKER.decode()])
        self.assertEqual(inline.returncode, 0, inline.stderr)
        self.assertTrue(json.loads(inline.stdout)['matched'])
        staged = self.run_argv(self.argv())
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.assertEqual(json.loads(staged.stdout),
                         {'matched': False, 'isolated': 1, 'no_bytecode': True})

    def test_wrong_sha_fails_before_any_checker_output(self):
        self.digest = '0' * 64
        result = self.run_argv(self.argv())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')

    def test_access_time_change_during_read_does_not_reject_unchanged_bytes(self):
        # This host mounts test paths with noatime. Simulate only the lstat
        # access-time observation that a relatime host can change on our read;
        # opening, hashing, permission checks and final exec remain real.
        argv = self.argv()
        prelude = f'''import pathlib,os
original_lstat=pathlib.Path.lstat
reads=0
def observed_lstat(p,*args,**kwargs):
 global reads
 value=original_lstat(p,*args,**kwargs)
 if str(p)=={str(self.script)!r}:
  reads+=1; fields=list(value)
  if reads>1:fields[7]+=1
  return os.stat_result(fields)
 return value
pathlib.Path.lstat=observed_lstat
'''
        argv[-1] = prelude + argv[-1]
        result = self.run_argv(argv)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)['matched'])

    def test_wrong_file_or_parent_modes_fail_before_execution(self):
        for file_mode, parent_mode in [(0o600, 0o700), (0o400, 0o755)]:
            with self.subTest(file_mode=file_mode, parent_mode=parent_mode):
                self.script.chmod(file_mode)
                self.parent.chmod(parent_mode)
                result = self.run_argv(self.argv())
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b'')
        self.parent.chmod(0o700)

    def test_symlink_file_or_parent_fails_before_execution(self):
        original = self.script
        self.script = self.parent / 'alias.py'
        self.script.symlink_to(original)
        result = self.run_argv(self.argv())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        link = self.parent / 'parent-alias'
        link.symlink_to(self.parent, target_is_directory=True)
        self.script = link / original.name
        result = self.run_argv(self.argv())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')

    def test_wrong_owner_fails_before_execution(self):
        if self.factory is None:
            argv = self.argv()
        else:
            argv = self.factory(sys.executable, str(self.script), self.digest,
                                owner_uid=os.getuid() + 1)
        result = self.run_argv(argv)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')

    def test_oversized_checker_fails_before_execution(self):
        result = self.run_argv(self.argv(max_bytes=1))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')

    def test_factory_rejects_unbounded_or_noncanonical_arguments_without_io(self):
        self.assertIsNotNone(self.factory, 'Common bounded argv factory missing')
        for key, value in [('max_bytes', 0), ('max_bytes', True),
                           ('max_bytes', 2**40), ('owner_uid', -1)]:
            with self.subTest(key=key, value=value):
                kwargs = {'owner_uid': os.getuid(), key: value}
                with self.assertRaises(ValueError):
                    self.factory(sys.executable, str(self.script), self.digest, **kwargs)
        for interpreter, script, digest in [
            ('python3', str(self.script), self.digest),
            (sys.executable, 'relative.py', self.digest),
            (sys.executable, '/tmp/../checker.py', self.digest),
            (sys.executable, str(self.script), 'not-a-sha'),
        ]:
            with self.subTest(script=script, interpreter=interpreter, digest=digest):
                with self.assertRaises(ValueError):
                    self.factory(interpreter, script, digest)


if __name__ == '__main__':
    unittest.main()
