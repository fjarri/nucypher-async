from enum import Enum


class Domain(Enum):
    MAINNET = "mainnet"
    IBEX = "ibex"
    ORYX = "oryx"

    @classmethod
    def from_string(cls, domain: str) -> "Domain":
        if domain == "mainnet":
            return cls.MAINNET
        elif domain == "ibex":
            return cls.IBEX
        elif domain == "oryx":
            return cls.ORYX
        else:
            raise ValueError(f"Unknown domain name: {domain}")
