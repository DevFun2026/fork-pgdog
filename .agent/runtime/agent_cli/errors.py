from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    FAILURE = 1
    USAGE = 2
    POLICY_BLOCKED = 3
    REVIEW_PENDING = 4
    INCOMPLETE = 5
