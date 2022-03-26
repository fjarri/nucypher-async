<%def name="main(ursula_server, code_info)">
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <link rel="stylesheet" type="text/css" href="https://fonts.googleapis.com/css?family=Open+Sans" />
</head>
<style type="text/css">

    body {
        font-family: "Open Sans", sans-serif;
        margin: 2em 2em 2em 2em;
    }

    /* unvisited link */
    a:link {
        color: #115;
        text-decoration-color: #bbb;
    }

    /* visited link */
    a:visited {
        color: #626;
    }

    table.this-node-info {
        vertical-align: top;
        margin-bottom: 2em;
    }

    table.this-node-info > tbody > tr > td {
        padding-left: 0;
        padding-right: 0.5em;
        vertical-align: top;
    }

    table.verified-nodes > tbody > tr > td {
        padding: 0 1em 0 0;
    }

    table.verified-nodes > thead > tr > td {
        border-bottom: 1px solid #ddd;
    }

    table.verified-nodes > tbody > tr > td {
        border-bottom: 1px solid #ddd;
    }

    h3 {
        margin-bottom: 0em;
    }

    .this-node {
        font-size: x-large;
    }

    .monospace {
        font-family: monospace;
    }
</style>
</body>
    <%
        verified_nodes = ursula_server.learner.fleet_sensor._verified_nodes
        contacts = ursula_server.learner.fleet_sensor._contacts_to_addresses

        if code_info.release:
            version_str = code_info.version
        elif code_info.git_revision:
            version_str = code_info.version + '+dev@' + code_info.git_revision[:8]
        else:
            version_str = code_info.version + '+dev'
    %>


    <table class="this-node-info">
        <tr>
            <td></td>
            <td><span class="this-node monospace">${ursula_server.staking_provider_address}</span></td>
        </tr>
        <tr>
            <td><div style="margin-bottom: 1em"></div></td>
            <td></td>
        </tr>
        <tr>
            <td><i>Running:</i></td>
            <td><span class="monospace">v${version_str}</span></td>
        </tr>
        %if code_info.diff:
        <tr>
            <td><i>Modifications:</i></td>
            <td>
            %for file_diff in code_info.diff:
            <span class="monospace">${file_diff.path} (+${file_diff.added}/-${file_diff.removed})</span><br/>
            %endfor
            </td>
        </tr>
        %endif
        <tr>
            <td><i>Domain:</i></td>
            <td><span class="monospace">${ ursula_server.ursula.domain }</span></td>
        </tr>
    </table>

    <h3>Verified nodes (${len(verified_nodes)} total)</h3>

    <table class="verified-nodes">
        <thead>
            <td></td>
            <td>Launched</td>
            <td>Verified</td>
        </thead>
        <tbody>
        %for node in verified_nodes.values():
            <tr>
                <td><span class="monospace">
                ${node.staking_provider_address}
                </span></td>
                <td></td>
                <td></td>
            </tr>
        %endfor
        </tbody>
    </table>

    <h3>Contacts (${len(contacts)} total)</h3>

    <table class="contacts">
        <thead>
            <td></td>
            <td>Possible addresses</td>
        </thead>
        <tbody>
        %for contact, addresses in contacts.items():
            <tr>
                <td><span class="monospace">${contact.host}:${contact.port}</span></td>
                <td>${addresses}</td>
            </tr>
        %endfor
        </tbody>
    </table>

</body>
</html>
</%def>
