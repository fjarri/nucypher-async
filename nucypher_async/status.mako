<%def name="main(server, code_info, is_active_peer)">
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
        padding-right: 1em;
        vertical-align: top;
    }

    table.verified-nodes > thead > tr > td {
        border-bottom: 1px solid #ddd;
        padding-left: 0;
        padding-right: 2em;
    }

    table.verified-nodes > tbody > tr > td {
        border-bottom: 1px solid #ddd;
        padding-right: 2em;
    }

    table.contacts > thead > tr > td {
        border-bottom: 1px solid #ddd;
        padding-left: 0;
        padding-right: 2em;
        padding-bottom: 0.5em;
    }

    table.contacts > tbody > tr > td {
        border-bottom: 1px solid #ddd;
        padding-left: 0;
        padding-right: 2em;
        padding-bottom: 0.5em;
        vertical-align: top;
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
        verified_node_entries = server.learner.fleet_sensor._verified_nodes_db._nodes
        verify_at = {
            entry.address: entry
            for entry in server.learner.fleet_sensor._verified_nodes_db._verify_at}

        if code_info.release:
            version_str = code_info.version
        elif code_info.git_revision:
            version_str = code_info.version + '+dev@' + code_info.git_revision[:8]
        else:
            version_str = code_info.version + '+dev'
    %>


    <table class="this-node-info">
        %if is_active_peer:
        <tr>
            <td></td>
            <td><span class="this-node monospace">${server.staking_provider_address}</span></td>
        </tr>
        %endif
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
            <td><span class="monospace">${ server.domain.value }</span></td>
        </tr>
        %if is_active_peer:
        <tr>
            <td><i>Metadata created:</i></td>
            <td>${arrow.get(server._metadata.payload.timestamp_epoch).humanize(now)}</td>
        </tr>
        %endif
        <tr>
            <td><i>Uptime:</i></td>
            <td>${humanize.naturaldelta(now - server._started_at)}</td>
        </tr>
    </table>

    <h3>Verified nodes (${len(verified_node_entries)} total)</h3>

    %if verified_node_entries:
    <table class="verified-nodes">
        <thead>
            <td></td>
            <td>Stake</td>
            <td>Metadata created</td>
            <td>Last verified</td>
            <td>Next verification</td>
        </thead>
        <tbody>
        %for address, node_entry in verified_node_entries.items():
            <%
                node = node_entry.node
                verify_at_entry = verify_at[address]
            %>
            <tr>
                <td><span class="monospace">
                <a href="https://${node.ssl_contact.contact.host}:${node.ssl_contact.contact.port}/status">${node.staking_provider_address}</a>
                </span></td>
                <td>${humanize.number.intword(int(node_entry.staked_amount.as_ether()))} T</td>
                <td>${arrow.get(node.metadata.payload.timestamp_epoch).humanize(now)}</td>
                <td>${node_entry.verified_at.humanize(now)}</td>
                <td>
                %if verify_at_entry.verify_at < now:
                was due ${verify_at_entry.verify_at.humanize(now)}
                %else:
                ${verify_at_entry.verify_at.humanize(now)}
                %endif
                </td>
            </tr>
        %endfor
        </tbody>
    </table>
    %endif

    <%
        contacts = server.learner.fleet_sensor._contacts_db._addresses_to_contacts
        staking_providers = server.learner.fleet_sensor._staking_providers
    %>

    <h3>Contacts (${len(contacts)} total)</h3>

    %if contacts:
    <table class="contacts">
        <thead>
            <td></td>
            <td>Stake</td>
            <td>Reported contact(s)</td>
        </thead>
        <tbody>
        %for address, contacts in contacts.items():
            <tr>
                <td>
                <span class="monospace">${address.as_checksum()}</span>
                </td>
                <td>
                %if address in staking_providers:
                ${humanize.number.intword(int(staking_providers[address].as_ether()))} T
                %else:
                &mdash;
                %endif
                </td>
                <td>
                %for contact in contacts:
                <a href="https://${contact.host}:${contact.port}/status">
                <span class="monospace">${contact.host}:${contact.port}</span>
                </a><br/>
                %endfor
                </td>
            </tr>
        %endfor
        </tbody>
    </table>
    %endif

</body>
</html>
</%def>
