// RDPGraph — front-end logic

const state = {
  sessionId: null,
  files: [],
  network: null,
  data: { nodes: null, edges: null },
};

const $ = (id) => document.getElementById(id);

// ------- File picker / drag-drop -------
const dz = $('dropzone');
const fileInput = $('fileInput');

// NOTE: #dropzone is a <label> wrapping #fileInput, so clicking it already
// opens the file picker natively. Do NOT call fileInput.click() here too, or
// the dialog opens twice (reopens right after the first selection).
['dragenter','dragover'].forEach(ev =>
  dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('drag'); }));
['dragleave','drop'].forEach(ev =>
  dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('drag'); }));

dz.addEventListener('drop', e => {
  const files = [...e.dataTransfer.files].filter(f => f.name.toLowerCase().endsWith('.evtx'));
  setFiles(files);
});
fileInput.addEventListener('change', () => setFiles([...fileInput.files]));

function setFiles(files) {
  state.files = files;
  const list = $('fileList');
  list.innerHTML = files.map(f =>
    `<div class="item">📄 ${f.name} <span style="color:#5a6573">(${(f.size/1024).toFixed(1)} KB)</span></div>`
  ).join('');
  $('uploadBtn').disabled = files.length === 0;
}

// ------- Upload + parse -------
$('uploadBtn').addEventListener('click', async () => {
  const fd = new FormData();
  state.files.forEach(f => fd.append('files', f));
  setStatus('parsing…', '');
  $('uploadBtn').disabled = true;

  try {
    const r = await fetch('/upload', { method: 'POST', body: fd });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error || 'upload failed');
    state.sessionId = j.session_id;
    renderGraph(j.graph);
    setStatus(`parsed ${j.files.length} file(s)`, 'ok');
    $('applyFilter').disabled = false;
    $('resetFilter').disabled = false;
  } catch (e) {
    setStatus('error: ' + e.message, 'error');
  } finally {
    $('uploadBtn').disabled = false;
  }
});

function setStatus(msg, cls) {
  const el = $('uploadStatus');
  el.textContent = msg;
  el.className = cls;
}

// ------- Filters -------
$('applyFilter').addEventListener('click', refreshGraph);
$('resetFilter').addEventListener('click', () => {
  $('filterUser').value = '';
  $('filterHost').value = '';
  $('filterStatus').value = '';
  refreshGraph();
});

async function refreshGraph() {
  if (!state.sessionId) return;
  const params = new URLSearchParams({
    user: $('filterUser').value,
    host: $('filterHost').value,
    status: $('filterStatus').value,
  });
  const r = await fetch(`/api/graph/${state.sessionId}?${params}`);
  const j = await r.json();
  renderGraph(j);
}

// ------- Render graph -------
function renderGraph(graph) {
  const s = graph.stats;
  let statsLine = `events: ${s.events} | nodes: ${s.nodes} | edges: ${s.edges} | failed: ${s.failed} | users: ${s.users}`;
  if (s.skipped_no_source) statsLine += ` | no-source: ${s.skipped_no_source}`;
  if (s.skipped_self_loop) statsLine += ` | self-loops: ${s.skipped_self_loop}`;
  $('stats').textContent = statsLine;

  // Empty-state when nothing to draw.
  const empty = $('emptyState');
  if (!graph.nodes.length) {
    empty.classList.remove('hidden');
    const breakdown = s.event_id_breakdown || {};
    const breakdownStr = Object.keys(breakdown).length
      ? Object.entries(breakdown).map(([id, n]) => `${id}×${n}`).join(', ')
      : '(no RDP-relevant events found)';
    $('emptyMsg').innerHTML =
      `Parsed <b>${s.events}</b> RDP-relevant events but none had a usable source host/IP.<br>` +
      `Event-ID breakdown: <code>${breakdownStr}</code>`;
    if (state.sessionId) {
      $('debugLink').textContent = `/api/debug/${state.sessionId}`;
    }
  } else {
    empty.classList.add('hidden');
  }

  const nodes = new vis.DataSet(graph.nodes.map(n => ({
    id: n.id, label: n.label, title: n.title, value: n.value,
    color: { background: n.color, border: '#0f1419', highlight: { background: n.color, border: '#5b8def' } },
    font: { color: '#dde1e7', size: 13 },
    shape: 'dot',
  })));
  const edges = new vis.DataSet(graph.edges.map((e, i) => ({
    id: 'e' + i,
    from: e.from, to: e.to,
    label: e.label, title: e.title,
    value: e.value, color: e.color, arrows: e.arrows,
    font: { color: '#e8ecf1', size: 14, align: 'horizontal',
            background: '#0b0e13', strokeWidth: 4, strokeColor: '#0b0e13' },
    smooth: { enabled: true, type: 'continuous', roundness: 0.2 },
    _meta: e,
  })));

  state.data = { nodes, edges };

  const options = {
    nodes: { scaling: { min: 12, max: 50 } },
    edges: {
      scaling: { min: 1, max: 6, label: false }, // scale width by weight, NOT the label text
      arrows: { to: { scaleFactor: 0.6 } },       // smaller, tidier arrowheads
    },
    physics: {
      solver: 'forceAtlas2Based',
      forceAtlas2Based: { gravitationalConstant: -50, springLength: 120 },
      stabilization: { iterations: 200 },
    },
    interaction: { hover: true, tooltipDelay: 150, navigationButtons: true,
                   dragNodes: true, dragView: true, zoomView: true },
  };

  const container = $('graph');
  if (state.network) state.network.destroy();
  state.network = new vis.Network(container, state.data, options);

  // Let physics lay the graph out once, then freeze it so nodes can be dragged
  // freely and stay put (otherwise the running solver fights/snaps them back).
  state.network.once('stabilizationIterationsDone', () => {
    state.network.setOptions({ physics: false });
  });

  state.network.on('selectNode', params => {
    if (params.nodes.length) showNodeDetail(params.nodes[0]);
  });
  state.network.on('deselectNode', hideDetail);
}

// ------- Detail panel -------
$('closeDetail').addEventListener('click', hideDetail);

function hideDetail() { $('detail').classList.add('hidden'); }

async function showNodeDetail(nodeId) {
  $('detailTitle').textContent = `Events touching: ${nodeId}`;
  $('detailBody').innerHTML = '<p style="color:#7c8794">loading…</p>';
  $('detail').classList.remove('hidden');

  const r = await fetch(`/api/events/${state.sessionId}?node=${encodeURIComponent(nodeId)}`);
  const events = await r.json();

  if (!events.length) {
    $('detailBody').innerHTML = '<p style="color:#7c8794">no matching events</p>';
    return;
  }

  const rows = events.slice(0, 200).map(e => `
    <tr>
      <td>${(e.timestamp || '').slice(0,19).replace('T',' ')}</td>
      <td>${e.event_id}</td>
      <td class="status-${e.status}">${e.status}</td>
      <td>${escape(e.user || '')}</td>
      <td>${escape(e.source_ip || e.source_host || '')}</td>
      <td>${escape(e.computer || '')}</td>
    </tr>`).join('');

  $('detailBody').innerHTML = `
    <table>
      <thead><tr><th>time</th><th>id</th><th>status</th><th>user</th><th>source</th><th>target</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <p style="color:#5a6573; font-size:11px; margin-top:8px">showing ${Math.min(events.length,200)} of ${events.length} events</p>
  `;
}

function escape(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}
