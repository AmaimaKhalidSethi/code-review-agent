"""
Example 2: Performance anti-patterns.
Expected findings: O(n^2) membership check in loop, repeated redundant
computation inside loop, inefficient data structure choice.
Good demo case for the performance pass specifically -- no security issues.
"""


def find_duplicates(items):
    duplicates = []
    for i in range(len(items)):
        for j in range(len(items)):
            # O(n^2) nested loop -- two passes would give O(n)
            if i != j and items[i] == items[j]:
                if items[i] not in duplicates:
                    duplicates.append(items[i])
    return duplicates


def process_records(records, blacklist):
    # blacklist is a list -- membership check is O(n) per iteration,
    # making the whole function O(n*m). A set() would make it O(n).
    results = []
    for record in records:
        if record["id"] not in blacklist:
            results.append(record)
    return results


def compute_stats(values):
    # len() and sum() both traverse the list -- called in a tight loop
    for i in range(1000):
        avg = sum(values) / len(values)
        minimum = min(values)
        maximum = max(values)

    return avg, minimum, maximum


def flatten(nested):
    result = []
    for sublist in nested:
        for item in sublist:
            # String concatenation inside a loop -- O(n^2) due to
            # immutable string re-allocation on every +=
            result += [str(item)]
    return result
