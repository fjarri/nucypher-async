import trio

from .server import serve_forever
from .ursula import Ursula, UrsulaServerConfig


def main():
    ursula = Ursula(0)
    ursula_server_config = UrsulaServerConfig(ursula, port=9151)
    serve_forever(ursula_server_config)
