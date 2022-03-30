from http import HTTPStatus
from pathlib import Path

import arrow
from mako import exceptions as mako_exceptions
from mako.template import Template

from .drivers.rest_client import HTTPError
from .version import CodeInfo


def render_status(logger, clock, ursula_server):

    BASE_DIR = Path(__file__).parent
    STATUS_TEMPLATE = Template(filename=str(BASE_DIR / "status.mako")).get_def('main')

    code_info = CodeInfo.collect()

    verified_node_entries = ursula_server.learner.fleet_sensor._verified_nodes_db._nodes
    verify_at = ursula_server.learner.fleet_sensor._verified_nodes_db._verify_at
    contacts = ursula_server.learner.fleet_sensor._contacts_db._contacts_to_addresses

    try:
        return STATUS_TEMPLATE.render(ursula_server, code_info, arrow=arrow, now=clock.utcnow())
    except Exception as e:
        text_error = mako_exceptions.text_error_template().render()
        html_error = mako_exceptions.html_error_template().render()
        logger.error("Template Rendering Exception:\n{}", text_error)
        raise HTTPError(html_error, HTTPStatus.INTERNAL_SERVER_ERROR) from e
