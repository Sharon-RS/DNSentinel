"""
Focused regression tests for DNSentinel single-instance detector lock.

Validates:
1. Lock acquisition creates the lock file and records the active detector PID.
2. Concurrent detector instance attempting lock acquisition is rejected with a clear RuntimeError.
3. Safe release of the lock upon shutdown allows subsequent detector instances to acquire it.
4. DNSentinel.start() lifecycle acquires lock before capture starts and releases it in finally.
5. DNSentinel.start() releases the lock even if packet capture is interrupted or raises an exception.
"""

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from main import DNSentinel


class TestDetectorLock(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.lock_path = os.path.join(self.temp_dir.name, "dnsentinel_detector.lock")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_default_lock_file_constant(self):
        """Verifies default lock file path is /tmp/dnsentinel_detector.lock."""
        self.assertEqual(DNSentinel.DEFAULT_LOCK_FILE, "/tmp/dnsentinel_detector.lock")
        detector = DNSentinel(pipeline_type="heuristic", enable_dashboard=False)
        self.assertEqual(detector.lock_file, "/tmp/dnsentinel_detector.lock")

    def test_acquire_and_release_lock_lifecycle(self):
        """Verifies acquiring lock creates file with PID and releasing cleans up fd."""
        detector = DNSentinel(
            pipeline_type="heuristic",
            enable_dashboard=False,
            lock_file=self.lock_path,
        )

        detector.acquire_lock()
        self.assertTrue(os.path.exists(self.lock_path))

        with open(self.lock_path, "r") as f:
            content = f.read().strip()
        self.assertEqual(content, str(os.getpid()))

        # Release lock
        detector.release_lock()
        self.assertIsNone(detector._lock_fd)

        # Should be re-acquirable cleanly
        detector.acquire_lock()
        self.assertIsNotNone(detector._lock_fd)
        detector.release_lock()

    def test_rejects_second_detector_instance(self):
        """Verifies that a second detector process trying to acquire the same lock is rejected."""
        detector1 = DNSentinel(
            pipeline_type="heuristic",
            enable_dashboard=False,
            lock_file=self.lock_path,
        )
        detector2 = DNSentinel(
            pipeline_type="cascade",
            enable_dashboard=False,
            lock_file=self.lock_path,
        )

        # Detector 1 acquires lock
        detector1.acquire_lock()

        # Detector 2 must be rejected with a clear RuntimeError
        with self.assertRaises(RuntimeError) as ctx:
            detector2.acquire_lock()

        error_message = str(ctx.exception)
        self.assertIn("Another DNSentinel detector process is already running", error_message)
        self.assertIn(self.lock_path, error_message)

        # Once detector 1 releases the lock, detector 2 must be able to acquire it
        detector1.release_lock()
        detector2.acquire_lock()
        self.assertIsNotNone(detector2._lock_fd)
        detector2.release_lock()

    def test_start_lifecycle_acquires_and_releases_lock(self):
        """Verifies start() holds lock during packet capture and releases it when finished."""
        detector = DNSentinel(
            pipeline_type="heuristic",
            enable_dashboard=False,
            lock_file=self.lock_path,
        )

        lock_held_during_capture = []

        def mock_capture_start(interface=None):
            # Verify lock is active during capture execution
            other = DNSentinel(
                pipeline_type="cascade",
                enable_dashboard=False,
                lock_file=self.lock_path,
            )
            try:
                other.acquire_lock()
                lock_held_during_capture.append(False)
            except RuntimeError:
                lock_held_during_capture.append(True)

        with patch("main.DNSCapture") as mock_capture_cls:
            mock_inst = MagicMock()
            mock_inst.start.side_effect = mock_capture_start
            mock_capture_cls.return_value = mock_inst

            detector.start(interface="test0")

        self.assertEqual(lock_held_during_capture, [True])
        # After start() returns, lock must be released
        self.assertIsNone(detector._lock_fd)

        # Another detector can now acquire immediately
        other = DNSentinel(
            pipeline_type="cascade",
            enable_dashboard=False,
            lock_file=self.lock_path,
        )
        other.acquire_lock()
        other.release_lock()

    def test_start_releases_lock_on_keyboard_interrupt(self):
        """Verifies start() releases the lock safely in finally block on KeyboardInterrupt."""
        detector = DNSentinel(
            pipeline_type="cascade",
            enable_dashboard=False,
            lock_file=self.lock_path,
        )

        with patch("main.DNSCapture") as mock_capture_cls:
            mock_inst = MagicMock()
            mock_inst.start.side_effect = KeyboardInterrupt("Ctrl+C simulation")
            mock_capture_cls.return_value = mock_inst

            with self.assertRaises(KeyboardInterrupt):
                detector.start(interface="test0")

        # Lock must be released despite interrupt
        self.assertIsNone(detector._lock_fd)

        # Another detector can acquire immediately
        detector2 = DNSentinel(
            pipeline_type="heuristic",
            enable_dashboard=False,
            lock_file=self.lock_path,
        )
        detector2.acquire_lock()
        detector2.release_lock()

    def test_start_rejects_second_instance_before_capture(self):
        """Verifies start() raises RuntimeError before initializing DNSCapture if already locked."""
        detector1 = DNSentinel(
            pipeline_type="heuristic",
            enable_dashboard=False,
            lock_file=self.lock_path,
        )
        detector2 = DNSentinel(
            pipeline_type="cascade",
            enable_dashboard=False,
            lock_file=self.lock_path,
        )

        detector1.acquire_lock()

        with patch("main.DNSCapture") as mock_capture_cls:
            with self.assertRaises(RuntimeError) as ctx:
                detector2.start(interface="test0")

            self.assertIn("Another DNSentinel detector process is already running", str(ctx.exception))
            mock_capture_cls.assert_not_called()

        detector1.release_lock()


if __name__ == "__main__":
    unittest.main()
