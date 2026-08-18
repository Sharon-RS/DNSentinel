from collections import deque


class SlidingWindowManager:
    """
    Maintains a sliding window of recent DNS observations
    independently for every host.
    """

    def __init__(self, window_size=20):

        self.window_size = window_size

        self.windows = {}

    # --------------------------------------------------
    # Create Window
    # --------------------------------------------------

    def create_window(self, host):

        self.windows[host] = deque(
            maxlen=self.window_size
        )

    # --------------------------------------------------
    # Update Window
    # --------------------------------------------------

    def update(self, host, domain, features):

        if host not in self.windows:
            self.create_window(host)

        observation = {
            "domain": domain,
            "entropy": float(features["entropy"]),
            "domain_length": int(features["domain_length"]),
            "query_type": features["query_type"]
        }

        self.windows[host].append(observation)

    # --------------------------------------------------
    # Get Statistics
    # --------------------------------------------------

    def get_statistics(self, host):

        if host not in self.windows:
            return self._empty_statistics()

        window = self.windows[host]

        if not window:
            return self._empty_statistics()

        total_entropy = sum(
            item["entropy"]
            for item in window
        )

        total_length = sum(
            item["domain_length"]
            for item in window
        )

        unique_domains = len(
            {
                item["domain"]
                for item in window
            }
        )

        # ----------------------------------------------
        # Trends
        # ----------------------------------------------

        if len(window) >= 2:

            entropy_trend = (
                window[-1]["entropy"]
                - window[0]["entropy"]
            )

            length_trend = (
                window[-1]["domain_length"]
                - window[0]["domain_length"]
            )

        else:

            entropy_trend = 0.0
            length_trend = 0.0

        # ----------------------------------------------
        # Statistics
        # ----------------------------------------------

        return {
            "window_size": len(window),

            "average_entropy": round(
                total_entropy / len(window),
                4
            ),

            "average_domain_length": round(
                total_length / len(window),
                4
            ),

            "unique_domains": unique_domains,

            "query_rate": len(window),

            "entropy_trend": round(
                entropy_trend,
                4
            ),

            "length_trend": round(
                length_trend,
                4
            )
        }

    # --------------------------------------------------
    # Empty Statistics
    # --------------------------------------------------

    @staticmethod
    def _empty_statistics():

        return {
            "window_size": 0,
            "average_entropy": 0.0,
            "average_domain_length": 0.0,
            "unique_domains": 0,
            "query_rate": 0,
            "entropy_trend": 0.0,
            "length_trend": 0.0
        }

    # --------------------------------------------------
    # Clear Window
    # --------------------------------------------------

    def clear(self, host):

        if host in self.windows:
            self.windows[host].clear()