/* ================================================================
   ArsenalOT Graph Viewer — app.js
   ================================================================ */
'use strict';

// ──────────────────────────────────────────────────────────────────
// PRESET QUERIES  (3 only)
// ──────────────────────────────────────────────────────────────────
const PRESET_QUERIES = [
    {
        title: "Mapa de Visibilidad",
        query: `MATCH (o:ORIGEN)-[]-(h:HOST)
WHERE h.DISCOVERY_SOURCE STARTS WITH 'active'
WITH COALESCE(o.LOCATION,'Desconocido') AS loc,
     h.NOMBRE_SUBRED AS nsub, h.SUBRED AS rsub, h.IP AS ip,
     max(h.ORGANIZACION) AS p_org, max(h.MAC) AS p_mac,
     max(h.SISTEMA) AS p_sistema, max(h.VENDOR) AS p_vendor,
     max(h.OS) AS p_os, max(h.CRITICO) AS p_critico, max(h.HOSTNAME) AS p_hostname
MERGE (vo:visibilitytest_Origen {name: loc})
MERGE (vnombre:visibilitytest_NombreSubred {id: loc+'_'+nsub}) SET vnombre.name=nsub
MERGE (vo)-[:VE_RED]->(vnombre)
MERGE (vrango:visibilitytest_RangoSubred {id: loc+'_'+rsub}) SET vrango.rango=rsub
MERGE (vnombre)-[:CONTIENE_RANGO]->(vrango)
MERGE (vh:visibilitytest_Host {id: loc+'_'+ip})
SET vh.IP=ip,vh.MAC=p_mac,vh.SISTEMA=p_sistema,vh.VENDOR=p_vendor,
    vh.OS=p_os,vh.CRITICO=p_critico,vh.HOSTNAME=p_hostname,vh.ORGANIZACION=p_org
MERGE (vrango)-[:CONTIENE_HOST]->(vh)
WITH count(vh) AS b1
MATCH (o:ORIGEN)-[]-(h:HOST)-[]-(s:SERVICE)
WHERE h.DISCOVERY_SOURCE STARTS WITH 'active'
WITH COALESCE(o.LOCATION,'Desconocido') AS loc, h.IP AS ip,
     s.port AS port, s.protocol AS protocol,
     max(s.name) AS p_name, max(s.product) AS p_product,
     max(s.version) AS p_version
MATCH (vh:visibilitytest_Host {id: loc+'_'+ip})
FOREACH (d IN CASE WHEN port IS NOT NULL THEN [1] ELSE [] END |
    MERGE (vsrv:visibilitytest_Servicio {id: loc+'_'+ip+'_'+toString(port)+'_'+protocol})
    SET vsrv.name=p_name,vsrv.port=port,vsrv.protocol=protocol,
        vsrv.product=p_product,vsrv.version=p_version,
        vsrv.etiqueta_visual=toString(port)+'/'+protocol
    MERGE (vh)-[:EXPONE_PUERTO]->(vsrv)
)
WITH count(vh) AS b2
MATCH (vo:visibilitytest_Origen) RETURN DISTINCT vo`
    },
    {
        title: "Mapa de Red Global",
        query: `MATCH (h:HOST) WHERE h.DISCOVERY_SOURCE STARTS WITH 'active'
WITH h.IP AS ip, max(h.ORGANIZACION) AS p_org, max(h.NOMBRE_SUBRED) AS p_nsub,
     max(h.SUBRED) AS p_rsub, max(h.MAC) AS p_mac, max(h.SISTEMA) AS p_sistema,
     max(h.VENDOR) AS p_vendor, max(h.OS) AS p_os, max(h.CRITICO) AS p_critico,
     max(h.HOSTNAME) AS p_hostname, max(h.DISCOVERY_SOURCE) AS p_disc
MERGE (org:networkmap_Organizacion {name: p_org})
MERGE (nSub:networkmap_NombreSubred {name: p_nsub})
MERGE (rSub:networkmap_RangoSubred {name: p_rsub})
MERGE (uh:networkmap_HostUnificado {IP: ip})
SET uh.MAC=p_mac,uh.SISTEMA=p_sistema,uh.VENDOR=p_vendor,uh.OS=p_os,
    uh.CRITICO=p_critico,uh.HOSTNAME=p_hostname,uh.DISCOVERY_SOURCE=p_disc,
    uh.ORGANIZACION=p_org,uh.NOMBRE_SUBRED=p_nsub,uh.SUBRED=p_rsub
MERGE (org)-[relOrg:TIENE_SUBRED]->(nSub)
MERGE (nSub)-[relRango:CONTIENE_RANGO]->(rSub)
MERGE (rSub)-[relHost:TIENE_HOST]->(uh)
WITH org,nSub,rSub,uh,relOrg,relRango,relHost,ip
OPTIONAL MATCH (h:HOST {IP:ip})-[]-(s:SERVICE)
WHERE h.DISCOVERY_SOURCE STARTS WITH 'active' AND s IS NOT NULL
WITH org,nSub,rSub,uh,relOrg,relRango,relHost,ip,
     s.port AS port, s.protocol AS protocol,
     max(s.name) AS p_name, max(s.product) AS p_product, max(s.version) AS p_version
FOREACH (d IN CASE WHEN port IS NOT NULL THEN [1] ELSE [] END |
    MERGE (usrv:networkmap_ServiceUnificado {id: ip+'_'+toString(port)+'_'+protocol})
    SET usrv.name=p_name,usrv.port=port,usrv.protocol=protocol,
        usrv.product=p_product,usrv.version=p_version,
        usrv.etiqueta_visual=toString(port)+'/'+protocol
    MERGE (uh)-[:EXPONE_SERVICIO]->(usrv)
)
RETURN DISTINCT org,nSub,rSub,uh,relOrg,relRango,relHost`
    },
    {
        title: "Camino de Ataque",
        query: `WITH 1 AS dummy
MATCH (o:ORIGEN)-[]-(h:HOST)
WHERE h.DISCOVERY_SOURCE STARTS WITH 'active'
  AND trim(toUpper(h.CRITICO)) IN ['SI','SÍ']
WITH DISTINCT COALESCE(o.LOCATION,'Desconocido') AS loc, h.IP AS ip,
     max(h.MAC) AS p_mac, max(h.ORGANIZACION) AS p_org,
     max(h.SISTEMA) AS p_sistema, max(h.VENDOR) AS p_vendor,
     max(h.OS) AS p_os, max(h.HOSTNAME) AS p_hostname
MERGE (vh:riskmap_HostCritico {IP: ip})
SET vh.MAC=p_mac,vh.SISTEMA=p_sistema,vh.VENDOR=p_vendor,
    vh.OS=p_os,vh.HOSTNAME=p_hostname,vh.ORGANIZACION=p_org,vh.CRITICO='SI'
MERGE (vo:riskmap_Origen {id: ip+'_'+loc}) SET vo.name=loc
MERGE (vh)-[rel:ACCESIBLE_DESDE]->(vo)
RETURN vh,vo,rel`
    }
];

// ──────────────────────────────────────────────────────────────────
// NODE STYLE MAP — shape + color per label type
// ──────────────────────────────────────────────────────────────────
const NODE_STYLES = {
    // Raw Neo4j labels
    'HOST':           { shape: 'dot',          color: '#4ECDC4', size: 18, legend: '● Host' },
    'SERVICE':        { shape: 'square',        color: '#FFE66D', size: 13, legend: '■ Servicio' },
    'ORIGEN':         { shape: 'diamond',       color: '#FF6B6B', size: 22, legend: '◆ Origen / Vector' },
    'ORGANIZACION':   { shape: 'star',          color: '#a78bfa', size: 24, legend: '★ Organización' },
    'VULNERABILITY':  { shape: 'hexagon',       color: '#f97316', size: 16, legend: '⬡ Vulnerabilidad' },
    'NETWORK':        { shape: 'triangleDown',  color: '#22c55e', size: 16, legend: '▼ Red' },
    // Structural labels from complex queries (matched by suffix after stripping prefix)
    'host':           { shape: 'dot',           color: '#4ECDC4', size: 18, legend: null },
    'hostunificado':  { shape: 'dot',           color: '#4ECDC4', size: 18, legend: null },
    'hostcritico':    { shape: 'dot',           color: '#ef4444', size: 20, legend: null },
    'servicio':       { shape: 'square',        color: '#FFE66D', size: 13, legend: null },
    'serviceunificado':{ shape: 'square',       color: '#FFE66D', size: 13, legend: null },
    'origen':         { shape: 'diamond',       color: '#FF6B6B', size: 22, legend: null },
    'organizacion':   { shape: 'star',          color: '#a78bfa', size: 24, legend: null },
    'nombredsubred':  { shape: 'triangleDown',  color: '#22c55e', size: 16, legend: null },
    'nombresubred':   { shape: 'triangleDown',  color: '#22c55e', size: 16, legend: null },
    'rangosubred':    { shape: 'triangle',      color: '#16a34a', size: 14, legend: null },
};

const LEGEND_ITEMS = [
    { style: NODE_STYLES['HOST'],         label: 'Host' },
    { style: NODE_STYLES['SERVICE'],      label: 'Servicio / Puerto' },
    { style: NODE_STYLES['ORIGEN'],       label: 'Origen / Vector' },
    { style: NODE_STYLES['ORGANIZACION'], label: 'Organización' },
    { style: NODE_STYLES['VULNERABILITY'],label: 'Vulnerabilidad' },
    { style: NODE_STYLES['NETWORK'],      label: 'Subred / Red' },
    { style: NODE_STYLES['hostcritico'],  label: 'Host Crítico', color: '#ef4444' },
];

// Shape → SVG symbol used in the legend
const SHAPE_SYMBOL = {
    dot:          '●', square: '■', diamond: '◆',
    star:         '★', hexagon: '⬡', triangle: '▲',
    triangleDown: '▼',
};

// ──────────────────────────────────────────────────────────────────
// STATE
// ──────────────────────────────────────────────────────────────────
let neoDriver       = null;
let visNetwork      = null;
let nodesDS         = null;
let edgesDS         = null;
let isConnected     = false;
let selectedOrg     = null;
let nodeTooltipData = new Map();
let edgeTooltipData = new Map();
let searchDebounce  = null;

// ──────────────────────────────────────────────────────────────────
// BOOTSTRAP
// ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initVisNetwork();
    buildLegend();
    bindEvents();
    autoConnect();
});

// ──────────────────────────────────────────────────────────────────
// VIS-NETWORK SETUP
// ──────────────────────────────────────────────────────────────────
function initVisNetwork() {
    const container = document.getElementById('graph-container');
    nodesDS = new vis.DataSet([]);
    edgesDS = new vis.DataSet([]);

    const options = {
        nodes: {
            font: {
                size: 11,
                color: '#dde5f0',
                face: 'Segoe UI, system-ui, sans-serif',
                strokeWidth: 3,
                strokeColor: 'rgba(9,13,24,.95)',
            },
            borderWidth: 1.5,
            borderWidthSelected: 2.5,
            shadow: { enabled: true, color: 'rgba(0,0,0,.45)', size: 7, x: 2, y: 2 },
        },
        edges: {
            arrows: { to: { enabled: true, scaleFactor: 0.5, type: 'arrow' } },
            color: {
                color:   'rgba(78,205,196,.22)',
                highlight: '#4ECDC4',
                hover:   'rgba(78,205,196,.55)',
                inherit: false,
            },
            font: {
                size: 9,
                color: '#3d5269',
                align: 'middle',
                background: 'rgba(9,13,24,.8)',
            },
            smooth: { type: 'continuous', roundness: 0.15 },
            width: 1.2,
            selectionWidth: 2.2,
            hoverWidth: 1.8,
        },
        physics: {
            enabled: true,
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {
                gravitationalConstant: -70,
                centralGravity: 0.006,
                springLength: 130,
                springConstant: 0.04,
                avoidOverlap: 0.4,
                damping: 0.35,
            },
            stabilization: { enabled: false },
            minVelocity: 0.5,
        },
        interaction: {
            hover: true,
            tooltipDelay: 99999,
            navigationButtons: false,
            keyboard: { enabled: true, bindToWindow: false },
            zoomView: true,
            dragView: true,
            multiselect: false,
        },
    };

    visNetwork = new vis.Network(container, { nodes: nodesDS, edges: edgesDS }, options);
    visNetwork.on('click',       onGraphClick);
    visNetwork.on('doubleClick', onGraphDoubleClick);
    visNetwork.on('hoverNode', params => {
        const d = nodeTooltipData.get(params.node);
        if (d) showCustomTooltip(d.labels, d.props, params.event);
    });
    visNetwork.on('blurNode',  () => hideCustomTooltip());
    visNetwork.on('hoverEdge', params => {
        const d = edgeTooltipData.get(params.edge);
        if (d) showCustomTooltip([d.type], d.props, params.event);
    });
    visNetwork.on('blurEdge',  () => hideCustomTooltip());
}

// ──────────────────────────────────────────────────────────────────
// NEO4J CONNECTION
// ──────────────────────────────────────────────────────────────────
async function autoConnect() {
    const cfg  = window.NEO4J_CONFIG || {};
    await connectToNeo4j(
        cfg.boltUrl  || 'bolt://localhost:7687',
        cfg.username || 'neo4j',
        cfg.password || 'neo4j123'
    );
}

async function connectToNeo4j(url, username, password) {
    setConnState('connecting', 'Conectando…');
    try {
        if (neoDriver) { try { await neoDriver.close(); } catch(_) {} neoDriver = null; }
        neoDriver = neo4j.driver(url, neo4j.auth.basic(username, password), {
            maxConnectionPoolSize: 5,
            connectionAcquisitionTimeout: 8000,
            disableLosslessIntegers: true,
        });
        await neoDriver.verifyConnectivity({ database: 'neo4j' });
        isConnected = true;
        setConnState('connected', url.replace('bolt://', ''));
        await fetchOrganizations();
    } catch (err) {
        isConnected = false;
        setConnState('disconnected', 'Error: ' + (err.message || '').substring(0, 80));
    }
}

function setConnState(state, label) {
    document.getElementById('conn-dot').className   = 'conn-dot ' + state;
    document.getElementById('conn-label').textContent = label;
}

// ──────────────────────────────────────────────────────────────────
// ORGANIZATION SELECTOR
// ──────────────────────────────────────────────────────────────────
async function fetchOrganizations() {
    const sel = document.getElementById('org-select');
    sel.innerHTML = '<option value="">Cargando…</option>';
    sel.disabled  = true;

    const session = neoDriver.session();
    try {
        const res = await session.run(
            'MATCH (h:HOST) WHERE h.ORGANIZACION IS NOT NULL ' +
            'RETURN DISTINCT h.ORGANIZACION AS org ORDER BY org'
        );
        const orgs = res.records.map(r => r.get('org')).filter(Boolean);
        sel.disabled = false;

        if (!orgs.length) {
            sel.innerHTML = '<option value="">Sin orgs en la DB</option>';
            setLeftPanelState(false);
            return;
        }

        sel.innerHTML = '<option value="">— Organización —</option>' +
            orgs.map(o => `<option value="${escHtml(o)}">${escHtml(o)}</option>`).join('');

        if (orgs.length === 1) { sel.value = orgs[0]; onOrgSelected(orgs[0]); }
        else                   { setLeftPanelState(false); }

    } catch(e) {
        sel.innerHTML = '<option value="">Error</option>';
    } finally {
        await session.close();
    }
}

function onOrgSelected(org) {
    selectedOrg = org || null;
    setLeftPanelState(!!org);
    clearGraph();
    if (!org) return;

    // Show overview on org select
    execQuery(
        'MATCH (n)-[r]->(m) WHERE n.ORGANIZACION = $org OR m.ORGANIZACION = $org ' +
        'RETURN n,r,m LIMIT 120',
        true, { org }
    );
}

function setLeftPanelState(enabled) {
    document.getElementById('left-panel').classList.toggle('no-org', !enabled);
    document.getElementById('run-query-btn').disabled =
        !enabled || !document.getElementById('query-select').value;
}

// ──────────────────────────────────────────────────────────────────
// NODE SEARCH
// ──────────────────────────────────────────────────────────────────
function searchNodes(term) {
    term = (term || '').trim();
    if (!term) { setSearchHint(''); return; }

    // 1. Try client-side: find matching nodes already in the graph
    const lower   = term.toLowerCase();
    const matches = nodesDS.get().filter(n => {
        const p = n._props || {};
        return (p.IP   && p.IP.toLowerCase().includes(lower))   ||
               (p.HOSTNAME && p.HOSTNAME.toLowerCase().includes(lower)) ||
               (p.name && p.name.toLowerCase().includes(lower));
    });

    if (matches.length > 0) {
        visNetwork.selectNodes(matches.map(n => n.id));
        visNetwork.focus(matches[0].id, { scale: 1.3,
            animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
        showNodePanel(matches[0]);
        setSearchHint(`${matches.length} coincidencia(s) en el grafo`);
        return;
    }

    // 2. Fallback: run a read-only Cypher search
    setSearchHint('Buscando en Neo4j…');
    const q = `
MATCH (h:HOST)
WHERE (toLower(h.IP) CONTAINS toLower($term) OR toLower(coalesce(h.HOSTNAME,'')) CONTAINS toLower($term))
  AND UPPER(h.ORGANIZACION) = UPPER($org)
WITH h LIMIT 20
OPTIONAL MATCH (h)-[]-(s:SERVICE)
OPTIONAL MATCH (o:ORIGEN)-[]-(h)
RETURN h, s, o`;

    execQuery(q, true, { term, org: selectedOrg || '' }).then(() => {
        const count = nodesDS.length;
        setSearchHint(count > 0 ? `${count} nodo(s) encontrado(s)` : 'Sin resultados');
    });
}

function setSearchHint(msg) {
    document.getElementById('search-hint').textContent = msg;
}

// ──────────────────────────────────────────────────────────────────
// QUERY EXECUTION
// ──────────────────────────────────────────────────────────────────
async function execQuery(cypher, clearFirst = true, params = {}) {
    if (!neoDriver || !isConnected) { return Promise.resolve(); }
    const trimmed = cypher.trim();
    if (!trimmed) return Promise.resolve();

    showOverlay(true, 'Ejecutando…');
    const session = neoDriver.session();
    try {
        const result = await session.run(trimmed, params);
        processRecords(result.records, clearFirst);
    } catch(err) {
        console.error('[Graph] Query error:', err);
        showOverlay(false);
        alert('Error en la consulta:\n' + (err.message || String(err)));
    } finally {
        await session.close();
        showOverlay(false);
    }
}

// ──────────────────────────────────────────────────────────────────
// RESULT PROCESSING
// ──────────────────────────────────────────────────────────────────
function processRecords(records, clearFirst) {
    const nodeMap = new Map();
    const edgeMap = new Map();
    let hasGraph  = false;
    const tabKeys = [], tabRows = [];

    for (const rec of records) {
        const tabRow = {};
        let rowHasScalar = false;

        for (const key of rec.keys) {
            const val = rec.get(key);
            if (val === null || val === undefined) { tabRow[key] = ''; rowHasScalar = true; continue; }
            if      (neo4j.isNode(val))         { hasGraph = true; collectNode(nodeMap, val); }
            else if (neo4j.isRelationship(val)) { hasGraph = true; collectEdge(edgeMap, val); }
            else if (neo4j.isPath(val))         { hasGraph = true; collectPath(nodeMap, edgeMap, val); }
            else {
                rowHasScalar = true;
                tabRow[key] = formatCellValue(val);
                if (!tabKeys.includes(key)) tabKeys.push(key);
            }
        }
        if (rowHasScalar) tabRows.push(tabRow);
    }

    if (hasGraph) {
        updateGraph(nodeMap, edgeMap, clearFirst);
        hideTableView();
    } else if (tabRows.length > 0) {
        renderTable(tabKeys, tabRows);
    } else {
        updateStats(0, 0, null);
    }
}

function nodePassesOrgFilter(props, labels) {
    if (!selectedOrg) return true;
    if (props.ORGANIZACION != null) return props.ORGANIZACION === selectedOrg;
    if (props.name != null && labels.some(l => /organizaci[oó]n/i.test(l)))
        return props.name === selectedOrg;
    return true;
}

// ──────────────────────────────────────────────────────────────────
// NODE / EDGE COLLECTION
// ──────────────────────────────────────────────────────────────────
function getNodeStyle(labels) {
    // 1. Exact match on known labels
    for (const lbl of labels) {
        if (NODE_STYLES[lbl]) return NODE_STYLES[lbl];
    }
    // 2. Strip prefix (e.g. "networkmap_HostUnificado" → "hostunificado")
    for (const lbl of labels) {
        const base = lbl.replace(/^[a-z]+_/i, '').toLowerCase();
        if (NODE_STYLES[base]) return NODE_STYLES[base];
    }
    // Default
    return { shape: 'dot', color: '#607080', size: 14, legend: null };
}

function collectNode(map, node) {
    const id = node.identity;
    if (map.has(id)) return;
    if (!nodePassesOrgFilter(node.properties, node.labels)) return;

    const style = getNodeStyle(node.labels);
    const label = getNodeDisplayLabel(node.labels, node.properties);

    nodeTooltipData.set(id, { labels: node.labels, props: node.properties });

    map.set(id, {
        id,
        label,
        shape: style.shape,
        size:  style.size,
        color: {
            background: style.color,
            border:     darken(style.color, 45),
            highlight:  { background: lighten(style.color, 28), border: style.color },
            hover:      { background: lighten(style.color, 16), border: style.color },
        },
        _labels: node.labels,
        _props:  node.properties,
    });
}

function collectEdge(map, rel) {
    const id = rel.identity;
    if (map.has(id)) return;
    edgeTooltipData.set(id, { type: rel.type, props: rel.properties });
    map.set(id, {
        id,
        from:   rel.start,
        to:     rel.end,
        label:  rel.type,
        _type:  rel.type,
        _props: rel.properties,
    });
}

function collectPath(nodeMap, edgeMap, path) {
    if (path.start) collectNode(nodeMap, path.start);
    if (path.end)   collectNode(nodeMap, path.end);
    for (const seg of (path.segments || [])) {
        collectNode(nodeMap, seg.start);
        collectNode(nodeMap, seg.end);
        collectEdge(edgeMap, seg.relationship);
    }
}

function updateGraph(nodeMap, edgeMap, clearFirst) {
    if (clearFirst) clearGraph(false);

    const newNodes = [], newEdges = [];
    for (const [id, n] of nodeMap) if (!nodesDS.get(id)) newNodes.push(n);
    for (const [id, e] of edgeMap) if (!edgesDS.get(id)) newEdges.push(e);

    nodesDS.add(newNodes);
    edgesDS.add(newEdges);

    updateStats(nodesDS.length, edgesDS.length, null);
    setEmptyState(nodesDS.length === 0);

    if (nodesDS.length > 0) {
        visNetwork.fit({ animation: false });
        fetchEdgesBetweenNodes().then(() => {
            setTimeout(() => visNetwork.fit({ animation: { duration: 450, easingFunction: 'easeInOutQuad' } }), 550);
        });
    }
}

function clearGraph(resetPanel = true) {
    nodesDS.clear();
    edgesDS.clear();
    nodeTooltipData.clear();
    edgeTooltipData.clear();
    updateStats(0, 0, null);
    setEmptyState(true);
    if (resetPanel) hideRightPanel();
    hideCustomTooltip();
    setSearchHint('');
}

// ──────────────────────────────────────────────────────────────────
// NODE LABEL HELPERS
// ──────────────────────────────────────────────────────────────────
const DISPLAY_PROP_PRIORITY = [
    'IP','name','HOSTNAME','port','LOCATION','ORGANIZACION',
    'etiqueta_visual','rango','id',
];

function getNodeDisplayLabel(labels, props) {
    for (const key of DISPLAY_PROP_PRIORITY) {
        if (props[key] !== undefined && props[key] !== null) {
            let v = String(props[key]);
            return v.length > 22 ? v.substring(0, 20) + '…' : v;
        }
    }
    for (const [, v] of Object.entries(props)) {
        if (v !== null && v !== undefined) {
            let s = String(v);
            return s.length > 22 ? s.substring(0, 20) + '…' : s;
        }
    }
    return labels[0] || 'Node';
}

// ──────────────────────────────────────────────────────────────────
// LEGEND
// ──────────────────────────────────────────────────────────────────
function buildLegend() {
    const div = document.getElementById('legend-items');
    div.innerHTML = LEGEND_ITEMS.map(item => {
        const sym   = SHAPE_SYMBOL[item.style.shape] || '●';
        const color = item.color || item.style.color;
        return `<div class="legend-row">
            <span class="legend-shape" style="color:${color};font-size:1rem">${sym}</span>
            <span>${escHtml(item.label)}</span>
        </div>`;
    }).join('');
}

// ──────────────────────────────────────────────────────────────────
// CUSTOM TOOLTIP
// ──────────────────────────────────────────────────────────────────
function showCustomTooltip(labels, props, event) {
    const tt  = document.getElementById('custom-tooltip');
    const MAX = 8;
    const entries = Object.entries(props)
        .filter(([,v]) => v !== null && v !== undefined)
        .slice(0, MAX);

    let html = `<div class="tt-label">${escHtml(labels.join(', '))}</div>`;
    for (const [k, v] of entries) {
        const d = String(v).length > 65 ? String(v).substring(0, 63) + '…' : String(v);
        html += `<div class="tt-row"><span class="tt-key">${escHtml(k)}</span><span class="tt-val">${escHtml(d)}</span></div>`;
    }
    const total = Object.keys(props).length;
    if (total > MAX) html += `<div class="tt-more">+${total - MAX} más…</div>`;

    tt.innerHTML = html;
    tt.classList.remove('hidden');
    positionTooltip(tt, event);
}

function hideCustomTooltip() {
    document.getElementById('custom-tooltip').classList.add('hidden');
}

function positionTooltip(tt, event) {
    if (!event) return;
    const x = event.clientX !== undefined ? event.clientX : (event.pageX || 0);
    const y = event.clientY !== undefined ? event.clientY : (event.pageY || 0);
    const mx = 14;
    tt.style.left = (x + mx) + 'px';
    tt.style.top  = (y - mx) + 'px';
    requestAnimationFrame(() => {
        const r = tt.getBoundingClientRect();
        if (r.right  > window.innerWidth  - 8) tt.style.left = (x - r.width  - mx) + 'px';
        if (r.bottom > window.innerHeight - 8) tt.style.top  = (y - r.height - mx) + 'px';
    });
}

// ──────────────────────────────────────────────────────────────────
// AUTO-FETCH EDGES BETWEEN VISIBLE NODES
// ──────────────────────────────────────────────────────────────────
async function fetchEdgesBetweenNodes() {
    const ids = nodesDS.getIds();
    if (!neoDriver || !isConnected || ids.length < 2) return;
    const session = neoDriver.session();
    try {
        const result = await session.run(
            'MATCH (a)-[r]->(b) WHERE id(a) IN $ids AND id(b) IN $ids RETURN r', { ids }
        );
        const edgeMap = new Map();
        for (const rec of result.records) {
            const rel = rec.get('r');
            if (neo4j.isRelationship(rel)) collectEdge(edgeMap, rel);
        }
        const newEdges = [];
        for (const [id, e] of edgeMap) if (!edgesDS.get(id)) newEdges.push(e);
        if (newEdges.length) {
            edgesDS.add(newEdges);
            updateStats(nodesDS.length, edgesDS.length, null);
        }
    } catch(e) {
        console.warn('[Graph] fetchEdgesBetweenNodes:', e.message);
    } finally {
        await session.close();
    }
}

// ──────────────────────────────────────────────────────────────────
// GRAPH EVENTS
// ──────────────────────────────────────────────────────────────────
function onGraphClick(params) {
    if (params.nodes.length > 0) {
        const node = nodesDS.get(params.nodes[0]);
        if (node) showNodePanel(node);
    } else if (params.edges.length > 0) {
        const edge = edgesDS.get(params.edges[0]);
        if (edge) showEdgePanel(edge);
    } else {
        hideRightPanel();
    }
}

function onGraphDoubleClick(params) {
    if (params.nodes.length > 0) {
        execQuery(
            `MATCH (n)-[r]-(m) WHERE id(n) = ${params.nodes[0]} RETURN n,r,m LIMIT 80`,
            false
        );
    }
}

// ──────────────────────────────────────────────────────────────────
// RIGHT PANEL
// ──────────────────────────────────────────────────────────────────
function showNodePanel(node) {
    const pill = document.getElementById('rp-type-pill');
    pill.textContent = 'Nodo'; pill.className = 'type-pill node';

    const style = getNodeStyle(node._labels || []);
    document.getElementById('rp-labels').innerHTML = (node._labels || []).map(l =>
        `<span class="lbl-chip" style="border-color:${style.color}50;color:${style.color}">${l}</span>`
    ).join('');

    renderPropList(node._props || {});
    const nb = visNetwork.getConnectedNodes(node.id);
    const ed = visNetwork.getConnectedEdges(node.id);
    document.getElementById('rp-context-text').textContent =
        `${nb.length} vecino(s) · ${ed.length} relación(es)`;
    openRightPanel();
}

function showEdgePanel(edge) {
    const pill = document.getElementById('rp-type-pill');
    pill.textContent = 'Relación'; pill.className = 'type-pill rel';
    document.getElementById('rp-labels').innerHTML =
        `<span class="lbl-chip" style="color:#a78bfa;border-color:#7c3aed50">${edge._type || '?'}</span>`;
    renderPropList(edge._props || {});
    document.getElementById('rp-context-text').textContent = `${edge.from} → ${edge.to}`;
    openRightPanel();
}

function renderPropList(props) {
    const entries = Object.entries(props).filter(([,v]) => v !== null && v !== undefined);
    document.getElementById('rp-props').innerHTML = entries.length === 0
        ? '<div class="prop-entry"><span style="color:var(--text-dim);font-size:.75rem;">Sin propiedades</span></div>'
        : entries.map(([k,v]) =>
            `<div class="prop-entry"><div class="prop-k">${escHtml(k)}</div><div class="prop-v">${escHtml(formatCellValue(v))}</div></div>`
          ).join('');
}

function openRightPanel()  { document.getElementById('right-panel').classList.remove('hidden'); }
function hideRightPanel()  { document.getElementById('right-panel').classList.add('hidden'); }

// ──────────────────────────────────────────────────────────────────
// TABLE VIEW
// ──────────────────────────────────────────────────────────────────
function renderTable(keys, rows) {
    document.getElementById('table-label').textContent = `${rows.length} fila(s)`;
    let html = '<table><thead><tr>' + keys.map(k => `<th>${escHtml(k)}</th>`).join('') + '</tr></thead><tbody>';
    for (const row of rows)
        html += '<tr>' + keys.map(k => `<td>${escHtml(String(row[k] ?? ''))}</td>`).join('') + '</tr>';
    html += '</tbody></table>';
    document.getElementById('table-scroll').innerHTML = html;
    document.getElementById('table-container').classList.remove('hidden');
    updateStats(0, 0, rows.length);
}

function hideTableView() { document.getElementById('table-container').classList.add('hidden'); }

// ──────────────────────────────────────────────────────────────────
// UI HELPERS
// ──────────────────────────────────────────────────────────────────
function showOverlay(show, msg) {
    const el = document.getElementById('graph-overlay');
    if (show) { if (msg) document.getElementById('overlay-msg').textContent = msg; el.classList.remove('hidden'); }
    else      { el.classList.add('hidden'); }
}

function setEmptyState(isEmpty) {
    document.getElementById('graph-empty').classList.toggle('hidden', !isEmpty);
}

function updateStats(nodes, edges, rows) {
    const el = document.getElementById('graph-stats');
    el.textContent = rows !== null && rows !== undefined
        ? `${rows} filas`
        : `${nodes ?? nodesDS.length} nodos · ${edges ?? edgesDS.length} relaciones`;
}

// ──────────────────────────────────────────────────────────────────
// EVENT BINDINGS
// ──────────────────────────────────────────────────────────────────
function bindEvents() {
    // Org selector
    document.getElementById('org-select').addEventListener('change', e => onOrgSelected(e.target.value));

    // Reconnect
    document.getElementById('reconnect-btn').addEventListener('click', autoConnect);

    // Query dropdown — enable run btn when value chosen
    document.getElementById('query-select').addEventListener('change', e => {
        document.getElementById('run-query-btn').disabled = !e.target.value || !selectedOrg;
    });

    // Run preset query
    document.getElementById('run-query-btn').addEventListener('click', () => {
        const idx = parseInt(document.getElementById('query-select').value, 10);
        if (isNaN(idx) || idx < 0 || idx >= PRESET_QUERIES.length) return;
        execQuery(PRESET_QUERIES[idx].query, true);
    });

    // Node search — trigger on Enter or button
    document.getElementById('node-search-btn').addEventListener('click', () => {
        searchNodes(document.getElementById('node-search').value);
    });

    document.getElementById('node-search').addEventListener('keydown', e => {
        if (e.key === 'Enter') searchNodes(e.target.value);
    });

    // Live client-side highlight while typing (debounced, client-only)
    document.getElementById('node-search').addEventListener('input', e => {
        clearTimeout(searchDebounce);
        const term = e.target.value.trim();
        if (!term) { setSearchHint(''); visNetwork.unselectAll(); return; }
        searchDebounce = setTimeout(() => {
            const lower   = term.toLowerCase();
            const matches = nodesDS.get().filter(n => {
                const p = n._props || {};
                return (p.IP   && p.IP.toLowerCase().includes(lower))   ||
                       (p.HOSTNAME && p.HOSTNAME.toLowerCase().includes(lower));
            });
            if (matches.length > 0) {
                visNetwork.selectNodes(matches.map(n => n.id));
                setSearchHint(`${matches.length} en grafo`);
            } else {
                setSearchHint('Pulsa → para buscar en Neo4j');
            }
        }, 200);
    });

    // Fit / Clear
    document.getElementById('fit-btn').addEventListener('click', () =>
        visNetwork && visNetwork.fit({ animation: { duration: 300, easingFunction: 'easeInOutQuad' } }));

    document.getElementById('clear-btn').addEventListener('click', () => clearGraph());

    // Physics toggle
    document.getElementById('physics-toggle').addEventListener('change', e =>
        visNetwork && visNetwork.setOptions({ physics: { enabled: e.target.checked } }));

    // Right panel close
    document.getElementById('rp-close').addEventListener('click', hideRightPanel);

    // Back to graph from table
    document.getElementById('back-to-graph-btn').addEventListener('click', hideTableView);

    // Move tooltip with mouse
    document.addEventListener('mousemove', e => {
        const tt = document.getElementById('custom-tooltip');
        if (!tt.classList.contains('hidden')) positionTooltip(tt, e);
    });
}

// ──────────────────────────────────────────────────────────────────
// COLOR MATH
// ──────────────────────────────────────────────────────────────────
function darken(hex, amt)  { return adjustHex(hex, -Math.abs(amt)); }
function lighten(hex, amt) { return adjustHex(hex,  Math.abs(amt)); }

function adjustHex(hex, amt) {
    const n = parseInt((hex || '#888').replace('#','').padEnd(6,'0'), 16);
    const r = Math.min(255, Math.max(0, (n >> 16)         + amt));
    const g = Math.min(255, Math.max(0, ((n >> 8) & 0xff) + amt));
    const b = Math.min(255, Math.max(0, (n & 0xff)        + amt));
    return '#' + [r,g,b].map(v => v.toString(16).padStart(2,'0')).join('');
}

// ──────────────────────────────────────────────────────────────────
// UTILS
// ──────────────────────────────────────────────────────────────────
function formatCellValue(val) {
    if (val === null || val === undefined) return '';
    if (Array.isArray(val)) return val.map(formatCellValue).join(', ');
    if (typeof val === 'object') {
        if (typeof val.toNumber === 'function') return String(val.toNumber());
        return JSON.stringify(val);
    }
    return String(val);
}

function escHtml(s) {
    return String(s)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
