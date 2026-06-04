let ws, reconnTimer, uptimeTimer, startTime;

function connect() {
    ws = new WebSocket('ws://' + location.host + '/ws');

    ws.onopen = () => {
        setConnected(true);
        clearTimeout(reconnTimer);
    };

    ws.onclose = () => {
        setConnected(false);
        reconnTimer = setTimeout(connect, 3000);
    };

    ws.onerror = () => setConnected(false);

    ws.onmessage = e => handle(JSON.parse(e.data));
}

function setConnected(ok) {
    document.getElementById('dot').className = 'dot' + (ok ? ' on' : '');
    document.getElementById('statusText').textContent = ok
        ? 'Connected'
        : 'Disconnected. Retrying...';
}

function handle(msg) {
    if (msg.type === 'stats') {
        updateStats(msg.data);
    } else if (msg.type === 'response_action' || msg.type === 'threat_assessment') {
        addRow(msg);
    }
}

function updateStats(d) {
    document.getElementById('sAlerts').textContent = d.alerts;
    document.getElementById('sSuspend').textContent = d.suspensions;
    document.getElementById('sQuarantine').textContent = d.quarantines;

    if (!startTime && d.uptime_seconds != null) {
        startTime = Date.now() - d.uptime_seconds * 1000;
        if (!uptimeTimer) uptimeTimer = setInterval(tickUptime, 1000);
    }
}

function tickUptime() {
    if (!startTime) return;
    const s = Math.floor((Date.now() - startTime) / 1000);
    const h = String(Math.floor(s / 3600)).padStart(2, '0');
    const m = String(Math.floor(s % 3600 / 60)).padStart(2, '0');
    const sc = String(s % 60).padStart(2, '0');
    document.getElementById('sUptime').textContent = h + ':' + m + ':' + sc;
}

function addRow(msg) {
    document.getElementById('empty').style.display = 'none';
    const tbl = document.getElementById('tbl');
    tbl.style.display = 'table';

    const d = msg.data;
    const t = new Date(msg.timestamp * 1000).toLocaleTimeString();
    const score = d.score || 0;

    let badgeClass, scoreColor, labelText;

    if (msg.type === 'response_action') {
        const k = d.kind;
        if (k === 'ALERT') {
            badgeClass = 'b-alert';
            scoreColor = '#fbbf24';
            labelText = 'Alert';
        } else if (k === 'SUSPEND') {
            badgeClass = 'b-suspend';
            scoreColor = '#f97316';
            labelText = 'Suspend';
        } else if (k === 'QUARANTINE') {
            badgeClass = 'b-quarantine';
            scoreColor = '#ef4444';
            labelText = 'Quarantine';
        } else {
            badgeClass = 'b-assess';
            scoreColor = '#3b82f6';
            labelText = k;
        }
    } else {
        badgeClass = 'b-assess';
        labelText = 'Assessment';
        scoreColor = score >= 75 ? '#ef4444'
            : score >= 55 ? '#f97316'
            : score >= 30 ? '#fbbf24'
            : '#22c55e';
    }

    const fname = d.path
        ? d.path.replace(/\\\\/g, '/').split('/').pop()
        : 'N/A';

    const sigs = (d.signals || [])
        .map(s => '<span class="sig">' + s.replace(/_/g, ' ') + '</span>')
        .join('') || (d.detail
            ? '<span class="sig">' + d.detail.substring(0, 40) + '</span>'
            : '');

    const tr = document.createElement('tr');
    tr.innerHTML =
        '<td>' + t + '</td>' +
        '<td><span class="badge ' + badgeClass + '">' + labelText + '</span></td>' +
        '<td>' +
            '<div class="score-wrap">' +
                '<span style="color:' + scoreColor + ';font-weight:700">' + score + '</span>' +
                '<div class="score-bar">' +
                    '<div class="score-fill" style="width:' + score + '%;background:' + scoreColor + '"></div>' +
                '</div>' +
            '</div>' +
        '</td>' +
        '<td class="path-cell" title="' + (d.path || '') + '">' + fname + '</td>' +
        '<td>' + sigs + '</td>' +
        '<td>' + (d.pid || 'N/A') + '</td>';

    const tbody = document.getElementById('tbody');
    tbody.insertBefore(tr, tbody.firstChild);

    while (tbody.children.length > 100) {
        tbody.removeChild(tbody.lastChild);
    }
}

function clearAll() {
    document.getElementById('tbody').innerHTML = '';
    document.getElementById('tbl').style.display = 'none';
    document.getElementById('empty').style.display = 'block';
}

connect();