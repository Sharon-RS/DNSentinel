from pathlib import Path


class Config:

    # ==========================================
    # PROJECT PATHS
    # ==========================================

    PROJECT_ROOT = Path(__file__).resolve().parents[2]

    DATA_DIR = PROJECT_ROOT / "data"

    PROFILE_DIR = DATA_DIR / "profiles"

    HISTORY_DIR = DATA_DIR / "history"

    DATASET_DIR = DATA_DIR / "datasets"

    MODEL_DIR = DATA_DIR / "models"

    LOG_DIR = PROJECT_ROOT / "logs"

    # ==========================================
    # FEATURE PARAMETERS
    # ==========================================

    SLIDING_WINDOW_SIZE = 20

    SLIDING_WINDOW_SECONDS = 60

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