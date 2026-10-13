from pathlib import Path
import os

class Config:

    # ==========================================
    # PROJECT PATHS
    # ==========================================

    PROJECT_ROOT = Path(__file__).resolve().parents[2]

    DATA_DIR = Path(
        os.environ.get(
            "DNSENTINEL_DATA_DIR",
            str(PROJECT_ROOT / "data")
        )
    )

    PROFILE_DIR = DATA_DIR / "profiles"

    HISTORY_DIR = DATA_DIR / "history"

    DATASET_DIR = DATA_DIR / "datasets"

    MODEL_DIR = DATA_DIR / "models"

    LOG_DIR = PROJECT_ROOT / "logs"

    @classmethod
    def set_data_dir(cls, custom_dir):
        """
        Explicitly reconfigure DATA_DIR and dependent subdirectories.
        Used for test and evaluation isolation.
        """
        cls.DATA_DIR = Path(custom_dir)
        cls.PROFILE_DIR = cls.DATA_DIR / "profiles"
        cls.HISTORY_DIR = cls.DATA_DIR / "history"
        cls.DATASET_DIR = cls.DATA_DIR / "datasets"
        cls.MODEL_DIR = cls.DATA_DIR / "models"
        os.environ["DNSENTINEL_DATA_DIR"] = str(custom_dir)

    @classmethod
    def get_data_dir(cls):
        """Return the currently configured data directory."""
        return cls.DATA_DIR

    # ==========================================
    # FEATURE PARAMETERS
    # ==========================================

    SLIDING_WINDOW_SIZE = 20

    SLIDING_WINDOW_SECONDS = 60

    # Configurable design threshold (queries/second) chosen for current prototype
    BASELINE_QUERY_RATE = 2.0

    # ==========================================
    # COLD-START CALIBRATION PARAMETERS
    # ==========================================

    COLD_START_CALIBRATION_QUERIES = 10
    MIN_ORG_CALIBRATION_QUERIES = 20
    CALIBRATION_MAX_ENTROPY = 4.5
    CALIBRATION_MAX_LENGTH = 45

    # ==========================================
    # RISK ENGINE
    # ==========================================

    RISK_DECAY = 0.90

    LOW_RISK = 20

    MEDIUM_RISK = 40

    HIGH_RISK = 70

    # ==========================================
    # MACHINE LEARNING
    # ==========================================

    RANDOM_SEED = 42

    TEST_SIZE = 0.20

    MODEL_NAME = "dnsentinel_rf.pkl"


    # Behavior Deviation Weights

    ENTROPY_WEIGHT = 0.25
    DOMAIN_LENGTH_WEIGHT = 0.20
    QUERY_RATE_WEIGHT = 0.15
    NOVEL_DOMAIN_WEIGHT = 0.20
    ORGANIZATION_RARITY_WEIGHT = 0.20

    # ----------------------------------------------------
    # Risk Thresholds
    # ----------------------------------------------------

    NORMAL_THRESHOLD = 25
    LOW_RISK_THRESHOLD = 50
    SUSPICIOUS_THRESHOLD = 75
    HIGH_RISK_THRESHOLD = 100