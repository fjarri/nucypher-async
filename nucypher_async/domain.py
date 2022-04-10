from enum import Enum


class Domain(Enum):
    MAINNET = "mainnet"
    IBEX = "ibex"

    @classmethod
    def from_string(cls, domain):
        if domain == "mainnet":
            return cls.MAINNET
        elif domain == "ibex":
            return cls.IBEX
        else:
            raise ValueError(f"Unknown domain name: {domain}")
