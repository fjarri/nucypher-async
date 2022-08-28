from http import HTTPStatus
from pathlib import Path

import arrow
import humanize
from mako import exceptions as mako_exceptions
from mako.template import Template

from .base.time import BaseClock
from .p2p.fleet_sensor import FleetSensor
from .verification import PublicUrsula
from .utils.logging import Logger
from .drivers.asgi_app import HTTPError
from .version import CodeInfo


def render_status(
    logger: Logger,
    clock: BaseClock,
    fleet_sensor: FleetSensor,
    node: PublicUrsula,
    started_at: arrow.Arrow,
    is_active_peer: bool,
) -> str:

    BASE_DIR = Path(__file__).parent
    STATUS_TEMPLATE = Template(filename=str(BASE_DIR / "status.mako")).get_def("main")

    code_info = CodeInfo.collect()

    try:
        return STATUS_TEMPLATE.render(
            fleet_sensor,
            node,
            started_at,
            code_info,
            is_active_peer,
            arrow=arrow,
            humanize=humanize,
            now=clock.utcnow(),
        )
    except Exception as exc:
        text_error = mako_exceptions.text_error_template().render()
        html_error = mako_exceptions.html_error_template().render()
        logger.error("Template Rendering Exception:\n{}", text_error)
        raise HTTPError(html_error, HTTPStatus.INTERNAL_SERVER_ERROR)
