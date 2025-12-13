from http import HTTPStatus
from pathlib import Path

import arrow
import humanize
from mako import exceptions as mako_exceptions
from mako.template import Template

from .._drivers.asgi import HTTPError
from .._drivers.time import BaseClock
from .._p2p import FleetSensorSnapshot, VerifiedNodeInfo
from ..domain import Domain
from ..logging import Logger
from ..version import CodeInfo

BASE_DIR = Path(__file__).parent
STATUS_TEMPLATE = Template(filename=str(BASE_DIR / "_status.mako")).get_def("main")


def render_status(
    logger: Logger,
    clock: BaseClock,
    snapshot: FleetSensorSnapshot,
    started_at: arrow.Arrow,
    domain: Domain,
    node: VerifiedNodeInfo | None = None,
) -> str:
    code_info = CodeInfo.collect()

    try:
        return STATUS_TEMPLATE.render(
            snapshot,
            node,
            domain,
            started_at,
            code_info,
            arrow=arrow,
            humanize=humanize,
            now=clock.utcnow(),
        )
    except Exception as exc:
        text_error = mako_exceptions.text_error_template().render()
        html_error = mako_exceptions.html_error_template().render()
        logger.error("Template Rendering Exception:\n{}", text_error)
        raise HTTPError(HTTPStatus.INTERNAL_SERVER_ERROR, html_error) from exc
