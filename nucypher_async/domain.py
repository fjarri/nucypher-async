from enum import Enum


class Domain(Enum):
    MAINNET = "mainnet"
    IBEX = "ibex"
    ORYX = "oryx"

    @classmethod
    def from_string(cls, domain: str) -> "Domain":
        if domain == "mainnet":
            return cls.MAINNET
        if domain == "ibex":
            return cls.IBEX
        if domain == "oryx":
            return cls.ORYX
        raise ValueError(f"Unknown domain name: {domain}")
