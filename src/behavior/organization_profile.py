import json
from pathlib import Path
from collections import Counter

from src.utils.config import Config


class OrganizationProfile:

    def __init__(self):

        self.profile_path = (
            Config.DATA_DIR /
            "organization" /
            "organization.json"
        )

        self.profile_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

    # ------------------------------------
    # Create Empty Profile
    # ------------------------------------

    def create_profile(self):

        return {

            "total_hosts": [],

            "total_queries": 0,

            "entropy_sum": 0.0,

            "domain_length_sum": 0,

            "average_entropy": 0.0,

            "average_domain_length": 0.0,

            "domain_frequency": {},

            "query_type_frequency": {},

            "host_domain_map": {}

        }

    # ------------------------------------
    # Load
    # ------------------------------------

    def load(self):

        if not self.profile_path.exists():

            profile = self.create_profile()

            self.save(profile)

            return profile

        with open(
            self.profile_path,
            "r"
        ) as file:

            return json.load(file)

    # ------------------------------------
    # Save
    # ------------------------------------

    def save(self, profile):

        with open(
            self.profile_path,
            "w"
        ) as file:

            json.dump(
                profile,
                file,
                indent=4
            )

    # ------------------------------------
    # Update
    # ------------------------------------

    def update(
        self,
        host,
        domain,
        features
    ):

        profile = self.load()

        if host not in profile["total_hosts"]:

            profile["total_hosts"].append(host)

        profile["total_queries"] += 1

        profile["entropy_sum"] += features["entropy"]

        profile["domain_length_sum"] += (
            features["domain_length"]
        )

        profile["average_entropy"] = round(

            profile["entropy_sum"] /
            profile["total_queries"],

            4
        )

        profile["average_domain_length"] = round(

            profile["domain_length_sum"] /
            profile["total_queries"],

            4
        )

        # Domain Frequency

        domain_frequency = Counter(

            profile["domain_frequency"]

        )

        domain_frequency[domain] += 1

        profile["domain_frequency"] = dict(
            domain_frequency
        )

        # Query Type Frequency

        query_frequency = Counter(

            profile["query_type_frequency"]

        )

        query_type = str(
            features["query_type"]
        )

        query_frequency[query_type] += 1

        profile["query_type_frequency"] = dict(
            query_frequency
        )

        # Host Domain Map

        host_map = profile["host_domain_map"]

        if domain not in host_map:

            host_map[domain] = []

        if host not in host_map[domain]:

            host_map[domain].append(host)

        profile["host_domain_map"] = host_map

        self.save(profile)

        return profile