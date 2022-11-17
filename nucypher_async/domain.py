from enum import Enum


class Domain(Enum):
    MAINNET = "mainnet"
    TAPIR = "tapir"
    LYNX = "lynx"

    @classmethod
    def from_string(cls, domain: str) -> "Domain":
        if domain == "mainnet":
            return cls.MAINNET
        if domain == "tapir":
            return cls.TAPIR
        if domain == "lynx":
            return cls.LYNX
        raise ValueError(f"Unknown domain name: {domain}")
