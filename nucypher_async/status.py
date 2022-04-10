from http import HTTPStatus
from pathlib import Path

import arrow
import humanize
from mako import exceptions as mako_exceptions
from mako.template import Template

from .drivers.rest_client import HTTPError
from .version import CodeInfo


def render_status(logger, clock, server, is_active_peer):

    BASE_DIR = Path(__file__).parent
    STATUS_TEMPLATE = Template(filename=str(BASE_DIR / "status.mako")).get_def('main')

    code_info = CodeInfo.collect()

    try:
        return STATUS_TEMPLATE.render(
            server, code_info, is_active_peer,
            arrow=arrow, humanize=humanize, now=clock.utcnow())
    except Exception as e:
        text_error = mako_exceptions.text_error_template().render()
        html_error = mako_exceptions.html_error_template().render()
        logger.error("Template Rendering Exception:\n{}", text_error)
        raise HTTPError(html_error, HTTPStatus.INTERNAL_SERVER_ERROR) from e
