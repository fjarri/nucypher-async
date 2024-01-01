from typing import Dict, List, Union

JSON = Union[str, int, float, bool, None, List["JSON"], Dict[str, "JSON"]]
