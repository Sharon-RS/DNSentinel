import os
import shutil
import tempfile
from pathlib import Path

from src.utils.config import Config
from src.pipeline.detection_pipeline import DetectionPipeline


class IsolatedEvaluationContext:
    """
    Guarantees strict isolation for tests and benchmark runs.

    Ensures:
      1. Live data directories (data/profiles, data/organization) are never touched.
      2. Config.DATA_DIR and all dependent subdirectories point to an isolated sandbox.
      3. Environment variable DNSENTINEL_DATA_DIR is synchronized.
      4. Original configuration is strictly restored upon context exit.
    """

    def __init__(self, sandbox_dir=None, clean_on_exit=True):
        self.custom_sandbox = sandbox_dir is not None
        self.clean_on_exit = clean_on_exit

        if sandbox_dir:
            self.sandbox_path = Path(sandbox_dir).resolve()
        else:
            self.sandbox_path = Path(
                tempfile.mkdtemp(prefix="dnsentinel_sandbox_")
            ).resolve()

        self._orig_data_dir = None
        self._orig_env_data_dir = None

    def __enter__(self):
        # Record original configuration
        self._orig_data_dir = Config.get_data_dir()
        self._orig_env_data_dir = os.environ.get("DNSENTINEL_DATA_DIR")

        # Create isolated subdirectories
        (self.sandbox_path / "profiles").mkdir(parents=True, exist_ok=True)
        (self.sandbox_path / "organization").mkdir(parents=True, exist_ok=True)

        # Redirect Config
        Config.set_data_dir(self.sandbox_path)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore Config
        if self._orig_data_dir is not None:
            Config.set_data_dir(self._orig_data_dir)

        # Restore environment variable
        if self._orig_env_data_dir is not None:
            os.environ["DNSENTINEL_DATA_DIR"] = self._orig_env_data_dir
        elif "DNSENTINEL_DATA_DIR" in os.environ:
            del os.environ["DNSENTINEL_DATA_DIR"]

        # Clean temporary sandbox if requested
        if not self.custom_sandbox and self.clean_on_exit:
            shutil.rmtree(self.sandbox_path, ignore_errors=True)

    def create_pipeline(self):
        """
        Instantiates a DetectionPipeline explicitly bound to the sandbox data directory.
        """
        return DetectionPipeline(data_dir=self.sandbox_path)
