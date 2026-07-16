import math
from collections import Counter


def calculate_entropy(text):

    if not text:
        return 0.0

    frequencies = Counter(text)

    text_length = len(text)

    entropy = 0.0

    for count in frequencies.values():

        probability = count / text_length

        entropy -= probability * math.log2(probability)

    return round(entropy, 4)
