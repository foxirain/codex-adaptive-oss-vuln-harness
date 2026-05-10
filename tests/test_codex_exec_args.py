import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from oss_harness.autopilot import _run_codex_exec as run_autopilot_codex_exec
from oss_harness.executor import run_codex_exec


class CodexExecArgsTests(unittest.TestCase):
    def test_executor_passes_model_and_reasoning_effort(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch('oss_harness.executor.subprocess.run') as mocked_run:
                mocked_run.return_value = subprocess.CompletedProcess([], 0, stdout='', stderr='')
                run_codex_exec(
                    repo_root=root,
                    prompt_text='prompt',
                    response_file=root / 'response.txt',
                    stdout_file=root / 'stdout.txt',
                    stderr_file=root / 'stderr.txt',
                    timeout_seconds=1,
                    model='gpt-5.5',
                    reasoning_effort='xhigh',
                    sandbox='workspace-write',
                    full_auto=True,
                    unsafe_bypass=False,
                )

            cmd = mocked_run.call_args.args[0]
            self.assertIn('-m', cmd)
            self.assertEqual(cmd[cmd.index('-m') + 1], 'gpt-5.5')
            self.assertIn('-c', cmd)
            self.assertEqual(cmd[cmd.index('-c') + 1], 'model_reasoning_effort="xhigh"')

    def test_autopilot_passes_model_and_reasoning_effort(self) -> None:
        class FakeProcess:
            pid = 12345

            def __init__(self) -> None:
                self.stdin = io.StringIO()
                self.stdout = io.StringIO('')
                self.stderr = io.StringIO('')

            def poll(self) -> int:
                return 0

            def kill(self) -> None:
                raise AssertionError('unexpected kill')

            def wait(self) -> int:
                return 0

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch('oss_harness.autopilot.subprocess.Popen') as mocked_popen:
                mocked_popen.return_value = FakeProcess()
                run_autopilot_codex_exec(
                    repo_root=str(root),
                    prompt_text='prompt',
                    response_file=root / 'response.txt',
                    stdout_path=root / 'stdout.txt',
                    stderr_path=root / 'stderr.txt',
                    timeout_seconds=1,
                    model='gpt-5.5',
                    reasoning_effort='xhigh',
                    sandbox='workspace-write',
                    full_auto=True,
                    unsafe_bypass=False,
                    watchdog_path=root / 'watchdog.txt',
                    watchdog_target='target',
                    watchdog_rank=1,
                )

            cmd = mocked_popen.call_args.args[0]
            self.assertIn('-m', cmd)
            self.assertEqual(cmd[cmd.index('-m') + 1], 'gpt-5.5')
            self.assertIn('-c', cmd)
            self.assertEqual(cmd[cmd.index('-c') + 1], 'model_reasoning_effort="xhigh"')


if __name__ == '__main__':
    unittest.main()
