(function(){
  'use strict';
  function $(id){ return document.getElementById(id); }

  var form = $('scan-form'), subnetEl = $('subnet'), portsEl = $('ports');
  var wantPortsEl = $('want-ports'), wantHostnamesEl = $('want-hostnames');
  var scanBtn = $('scan-btn'), stopBtn = $('stop-btn');
  var statusEl = $('status'), bodyEl = $('results-body'), emptyRow = $('empty-row');

  var rows = {};   // ip -> <tr>
  var es = null;

  try {
    var savedSubnet = localStorage.getItem('lansled/subnet');
    if (savedSubnet) subnetEl.value = savedSubnet;
  } catch (err) { /* storage unavailable: start fresh */ }

  function setStatus(text, kind){
    statusEl.textContent = text || '';
    statusEl.className = 'status' + (kind ? ' ' + kind : '');
  }

  function clearResults(){
    rows = {};
    bodyEl.textContent = '';
    bodyEl.appendChild(emptyRow);
    emptyRow.hidden = false;
  }

  function cell(text, cls){
    var td = document.createElement('td');
    if (cls) td.className = cls;
    td.textContent = text == null ? '' : text;
    return td;
  }

  function rowFor(ip){
    if (rows[ip]) return rows[ip];
    emptyRow.hidden = true;
    var tr = document.createElement('tr');
    tr.className = 'is-new';
    tr.appendChild(cell(ip, 'ip'));
    tr.appendChild(cell('—', 'mac'));
    tr.appendChild(cell('—', 'vendor'));
    tr.appendChild(cell('—', 'hostname'));
    var portsTd = document.createElement('td');
    portsTd.className = 'ports';
    portsTd.innerHTML = '<span class="dim">scanning…</span>';
    tr.appendChild(portsTd);
    // insert in numeric IP order, so the table doesn't jump around as hosts trickle in
    var ipKey = ip.split('.').map(function(n){ return ('000' + n).slice(-3); }).join('.');
    var next = null;
    for (var i = 0; i < bodyEl.children.length; i++) {
      var child = bodyEl.children[i];
      if (child === emptyRow || !child.dataset.ipKey) continue;
      if (child.dataset.ipKey > ipKey) { next = child; break; }
    }
    tr.dataset.ipKey = ipKey;
    bodyEl.insertBefore(tr, next);
    rows[ip] = tr;
    return tr;
  }

  function onEvent(ev){
    switch (ev.type) {
      case 'status': setStatus(ev.message); break;
      case 'warning': setStatus(ev.message, 'warn'); break;
      case 'error': setStatus(ev.message, 'err'); stopScan(); break;
      case 'host': {
        var tr = rowFor(ev.ip);
        tr.children[1].textContent = ev.mac || '—';
        tr.children[2].textContent = ev.vendor || (ev.mac ? 'Unknown' : '—');
        if (!wantPortsEl.checked) tr.children[4].innerHTML = '<span class="dim">—</span>';
        break;
      }
      case 'hostname': {
        var hr = rows[ev.ip]; if (hr) hr.children[3].textContent = ev.hostname;
        break;
      }
      case 'ports': {
        var pr = rows[ev.ip]; if (!pr) break;
        var td = pr.children[4];
        if (!ev.ports.length) { td.innerHTML = '<span class="dim">none open</span>'; break; }
        td.innerHTML = '';
        ev.ports.forEach(function(p){
          var chip = document.createElement('span');
          chip.className = 'port-chip';
          chip.textContent = p.port + (p.name ? ' ' + p.name : '');
          td.appendChild(chip);
        });
        break;
      }
      case 'done':
        setStatus(ev.count + ' device' + (ev.count === 1 ? '' : 's') + ' found in ' + ev.elapsed + 's.');
        stopScan();
        break;
    }
  }

  function startScan(){
    var subnet = subnetEl.value.trim();
    if (!subnet) return;
    try { localStorage.setItem('lansled/subnet', subnet); } catch (err) {}
    clearResults();
    setStatus('Starting…');
    scanBtn.disabled = true; stopBtn.hidden = false;
    var q = new URLSearchParams({
      subnet: subnet, ports: portsEl.value.trim(),
      ports_on: wantPortsEl.checked ? '1' : '0',
      hostnames_on: wantHostnamesEl.checked ? '1' : '0'
    });
    es = new EventSource('/api/scan?' + q.toString());
    es.onmessage = function(e){
      try { onEvent(JSON.parse(e.data)); } catch (err) { /* ignore a malformed event */ }
    };
    es.onerror = function(){
      if (es && es.readyState === EventSource.CLOSED) return;
      setStatus('Lost the connection to LanSled’s server.', 'err');
      stopScan();
    };
  }

  function stopScan(){
    if (es) { es.close(); es = null; }
    scanBtn.disabled = false; stopBtn.hidden = true;
  }

  form.addEventListener('submit', function(e){ e.preventDefault(); startScan(); });
  stopBtn.addEventListener('click', function(){ setStatus('Stopped.'); stopScan(); });
})();
