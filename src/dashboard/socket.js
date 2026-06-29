let ws, reconnTimer, uptimeTimer, startTime;

function connect() {
    ws = new WebSocket('ws://' + location.host + '/ws');
    ws.onopen = function() { clearTimeout(reconnTimer); };
    ws.onclose = function() { reconnTimer = setTimeout(connect, 3000); };
    ws.onerror = function() {};
    ws.onmessage = function(e) { handle(JSON.parse(e.data)); };
}

function handle(msg) {
    if (msg.type === 'stats') updateStats(msg.data);
    else if (msg.type === 'response_action' || msg.type === 'threat_assessment') addRow(msg);
}

function updateStats(d) {
    document.getElementById('sAlerts').textContent = d.alerts;
    document.getElementById('sSuspend').textContent = d.suspensions;
    document.getElementById('sQuarantine').textContent = d.quarantines;

    if (!startTime && d.uptime != null) {
        startTime = Date.now() - d.uptime * 1000;
        if (!uptimeTimer) uptimeTimer = setInterval(tickUptime, 1000);
    }
}

function tickUptime() {
    if (!startTime) return;
    var s = Math.floor((Date.now() - startTime) / 1000);
    var h = String(Math.floor(s / 3600)).padStart(2, '0');
    var m = String(Math.floor(s % 3600 / 60)).padStart(2, '0');
    var sc = String(s % 60).padStart(2, '0');
    document.getElementById('sUptime').textContent = h + ':' + m + ':' + sc;
}

function parseSignalsFromDetail(detail) {
    if (!detail) return [];
    var match = detail.match(/signals=\[([^\]]*)\]/);
    if (match && match[1]) {
        return match[1].split(',').map(function(s) { return s.trim(); }).filter(Boolean);
    }
    return [];
}

function addRow(msg) {
    document.getElementById('empty').style.display = 'none';
    var tbl = document.getElementById('tbl');
    tbl.style.display = 'table';

    var d = msg.data;
    var t = new Date(msg.timestamp * 1000).toLocaleTimeString();
    var score = d.score || 0;
    var levelClass, levelText, scoreClass;

    if (msg.type === 'response_action') {
        var k = d.kind;
        if (k === 'ALERT') { levelClass = 'level-alert'; levelText = 'Alert'; }
        else if (k === 'SUSPEND') { levelClass = 'level-suspend'; levelText = 'Suspend'; }
        else if (k === 'QUARANTINE') { levelClass = 'level-quarantine'; levelText = 'Quarantine'; }
        else { levelClass = 'level-assess'; levelText = k; }
    } else {
        levelClass = 'level-assess';
        levelText = 'Assessment';
    }

    if (score >= 75) scoreClass = 'score-high';
    else if (score >= 55) scoreClass = 'score-mid';
    else scoreClass = 'score-low';

    var fullPath = d.path
        ? d.path.replace(/\\\\/g, '/')
        : 'N/A';

    var signalList = d.signals || parseSignalsFromDetail(d.detail);

    var sigs = signalList
        .map(function(s) { return '<span class="sig">' + s.replace(/_/g, ' ') + '</span>'; })
        .join('');

    var tr = document.createElement('tr');
    tr.innerHTML =
        '<td>' + t + '</td>' +
        '<td><span class="level ' + levelClass + '">' + levelText + '</span></td>' +
        '<td><span class="score ' + scoreClass + '">' + score + '</span></td>' +
        '<td class="path-cell">' + fullPath + '</td>' +
        '<td class="signals-cell">' + sigs + '</td>' +
        '<td>' + (d.pid || 'N/A') + '</td>';

    var tbody = document.getElementById('tbody');
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