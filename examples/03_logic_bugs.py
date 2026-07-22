"""
Example 3: Logic bugs and edge case mishandling.
Expected findings: off-by-one in range, unhandled None, division without
zero-check, wrong variable used, incorrect conditional direction.
Good demo case for the bug pass specifically -- minimal style/security noise.
"""


def average(numbers):
    total = 0
    # Off-by-one: should be range(len(numbers)), not range(len(numbers) + 1)
    for i in range(len(numbers) + 1):
        total += numbers[i]
    return total / len(numbers)


def find_first_negative(values):
    for i, v in enumerate(values):
        if v < 0:
            return i
    # Falls off the end with no return -- implicit None when no negative
    # found, but the docstring claims to return an index


def safe_divide(a, b):
    # Missing zero-check -- will raise ZeroDivisionError
    return a / b


def parse_config(config):
    # config could be None but is used without a guard
    return config["host"], config["port"]


def is_adult(age):
    # Wrong comparison direction: should be >= 18, not > 18
    # (an 18-year-old is an adult)
    if age > 18:
        return True
    return False


def get_last_item(items):
    # Wrong index: should be -1 or len(items)-1, not len(items)
    return items[len(items)]
