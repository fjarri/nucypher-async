from typing import Any, Union, List, Dict


# TODO: make a proper type when `mypy` supports recursive type aliases
JSON = Union[str, int, float, bool, None, List[Any], Dict[str, Any]]
