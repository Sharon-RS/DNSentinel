import json
from pathlib import Path

from src.behavior.host_profile import HostProfile
from src.utils.config import Config


class HostProfileManager:

    def __init__(self):

        self.profile_dir = Config.DATA_DIR / "profiles"
        self.profile_dir.mkdir(parents=True, exist_ok=True)

    def _profile_path(self, host):

        safe_host = host.replace(":", "_")
        return self.profile_dir / f"{safe_host}.json"

    def load(self, host):

        path = self._profile_path(host)

        if not path.exists():
            return HostProfile(host)

        with open(path, "r") as file:
            data = json.load(file)

        return HostProfile.from_dict(data)

    def save(self, profile):

        path = self._profile_path(profile.host)

        with open(path, "w") as file:
            json.dump(
                profile.to_dict(),
                file,
                indent=4
            )

    def update(self, host, domain, features):

        profile = self.load(host)

        profile.update(domain, features)

        self.save(profile)

        return profile.to_dict()