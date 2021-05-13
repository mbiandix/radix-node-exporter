from enum import Enum

class Env(Enum): # pylint: disable=too-few-public-methods
    """ Enumeration for the running environments
    """
    PROD = "production"
    STG = "staging"
    DEV = "development"
