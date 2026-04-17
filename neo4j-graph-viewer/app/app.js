/* ================================================================
   ArsenalOT Graph Viewer — app.js
   Neo4j transport: HTTP REST API (port 7474) via fetch()
   ================================================================ */
'use strict';

// ──────────────────────────────────────────────────────────────────
// PRESET QUERIES — mismas que las publicadas en `static/data/neo4j_queries.json`
// (pestaña Neo4j de la app principal). Mantener en sincronía si se actualizan.
//
// Cada entrada declara:
//   id        — identificador estable
//   title     — texto del dropdown
//   needsExtra — si requiere parámetro extra del usuario
//                ('visibility-origin' | 'attack-target' | null)
//   query     — Cypher (con parámetros $org, $location, $target según haga falta)
// ──────────────────────────────────────────────────────────────────
const PRESET_QUERIES = [
    {
        id: 'visibility',
        title: "Mapa de Visibilidad",
        needsExtra: 'visibility-origin',
        // Pinta el árbol completo desde el origen indicado (no devuelve solo
        // los nodos `ORIGEN`, sino también las subredes, hosts y servicios
        // ya desplegados, evitando que el usuario tenga que hacer doble-click
        // para expandir cada rama).
        query: `MATCH (o:ORIGEN)-[]-(h:HOST)
WHERE h.DISCOVERY_SOURCE STARTS WITH 'active'
  AND h.ORGANIZACION = $org
  AND COALESCE(o.LOCATION,'Desconocido') = $location
WITH $org AS org_key, $location AS loc,
     h.NOMBRE_SUBRED AS nsub, h.SUBRED AS rsub, h.IP AS ip,
     max(h.ORGANIZACION) AS p_org, max(h.MAC) AS p_mac,
     max(h.SISTEMA) AS p_sistema, max(h.VENDOR) AS p_vendor,
     max(h.OS) AS p_os, max(h.CRITICO) AS p_critico, max(h.HOSTNAME) AS p_hostname
MERGE (vo:visibilitytest_Origen {id: org_key+'_'+loc}) SET vo.name=loc
MERGE (vnombre:visibilitytest_NombreSubred {id: org_key+'_'+loc+'_'+nsub}) SET vnombre.name=nsub
MERGE (vo)-[:VE_RED]->(vnombre)
MERGE (vrango:visibilitytest_RangoSubred {id: org_key+'_'+loc+'_'+rsub}) SET vrango.rango=rsub
MERGE (vnombre)-[:CONTIENE_RANGO]->(vrango)
MERGE (vh:visibilitytest_Host {id: org_key+'_'+loc+'_'+ip})
SET vh.IP=ip,vh.MAC=p_mac,vh.SISTEMA=p_sistema,vh.VENDOR=p_vendor,
    vh.OS=p_os,vh.CRITICO=p_critico,vh.HOSTNAME=p_hostname,vh.ORGANIZACION=p_org
MERGE (vrango)-[:CONTIENE_HOST]->(vh)
WITH org_key, loc, count(vh) AS b1
MATCH (o:ORIGEN)-[]-(h:HOST)-[]-(s:SERVICE)
WHERE h.DISCOVERY_SOURCE STARTS WITH 'active'
  AND h.ORGANIZACION = $org
  AND COALESCE(o.LOCATION,'Desconocido') = $location
WITH org_key, loc, h.IP AS ip,
     s.port AS port, s.protocol AS protocol,
     max(s.name) AS p_name, max(s.product) AS p_product,
     max(s.version) AS p_version
MATCH (vh:visibilitytest_Host {id: org_key+'_'+loc+'_'+ip})
FOREACH (d IN CASE WHEN port IS NOT NULL THEN [1] ELSE [] END |
    MERGE (vsrv:visibilitytest_Servicio {id: org_key+'_'+loc+'_'+ip+'_'+toString(port)+'_'+protocol})
    SET vsrv.name=p_name,vsrv.port=port,vsrv.protocol=protocol,
        vsrv.product=p_product,vsrv.version=p_version,
        vsrv.etiqueta_visual=toString(port)+'/'+protocol
    MERGE (vh)-[:EXPONE_PUERTO]->(vsrv)
)
WITH org_key, loc, count(*) AS b2
MATCH (vo:visibilitytest_Origen {id: org_key+'_'+loc})
OPTIONAL MATCH (vo)-[r1:VE_RED]->(vnombre:visibilitytest_NombreSubred)
OPTIONAL MATCH (vnombre)-[r2:CONTIENE_RANGO]->(vrango:visibilitytest_RangoSubred)
OPTIONAL MATCH (vrango)-[r3:CONTIENE_HOST]->(vh:visibilitytest_Host)
OPTIONAL MATCH (vh)-[r4:EXPONE_PUERTO]->(vsrv:visibilitytest_Servicio)
RETURN vo, vnombre, vrango, vh, vsrv, r1, r2, r3, r4`
    },
    {
        id: 'networkmap',
        title: "Mapa de Red Global",
        needsExtra: null,
        query: `MATCH (h:HOST) WHERE h.DISCOVERY_SOURCE STARTS WITH 'active'
  AND h.ORGANIZACION = $org
WITH $org AS org_key, h.IP AS ip, max(h.ORGANIZACION) AS p_org,
     max(h.NOMBRE_SUBRED) AS p_nsub, max(h.SUBRED) AS p_rsub,
     max(h.MAC) AS p_mac, max(h.SISTEMA) AS p_sistema,
     max(h.VENDOR) AS p_vendor, max(h.OS) AS p_os, max(h.CRITICO) AS p_critico,
     max(h.HOSTNAME) AS p_hostname, max(h.DISCOVERY_SOURCE) AS p_disc
MERGE (org:networkmap_Organizacion {name: p_org})
MERGE (nSub:networkmap_NombreSubred {id: p_org+'_'+p_nsub}) SET nSub.name=p_nsub
MERGE (rSub:networkmap_RangoSubred {id: p_org+'_'+p_rsub}) SET rSub.rango=p_rsub
MERGE (uh:networkmap_HostUnificado {id: p_org+'_'+ip})
SET uh.IP=ip,uh.MAC=p_mac,uh.SISTEMA=p_sistema,uh.VENDOR=p_vendor,uh.OS=p_os,
    uh.CRITICO=p_critico,uh.HOSTNAME=p_hostname,uh.DISCOVERY_SOURCE=p_disc,
    uh.ORGANIZACION=p_org,uh.NOMBRE_SUBRED=p_nsub,uh.SUBRED=p_rsub
MERGE (org)-[relOrg:TIENE_SUBRED]->(nSub)
MERGE (nSub)-[relRango:CONTIENE_RANGO]->(rSub)
MERGE (rSub)-[relHost:TIENE_HOST]->(uh)
WITH org_key,org,nSub,rSub,uh,relOrg,relRango,relHost,ip,p_org
OPTIONAL MATCH (h:HOST {IP:ip})-[]-(s:SERVICE)
WHERE h.DISCOVERY_SOURCE STARTS WITH 'active'
  AND h.ORGANIZACION = $org AND s IS NOT NULL
WITH org_key,org,nSub,rSub,uh,relOrg,relRango,relHost,ip,p_org,
     s.port AS port, s.protocol AS protocol,
     max(s.name) AS p_name, max(s.product) AS p_product, max(s.version) AS p_version
FOREACH (d IN CASE WHEN port IS NOT NULL THEN [1] ELSE [] END |
    MERGE (usrv:networkmap_ServiceUnificado {id: p_org+'_'+ip+'_'+toString(port)+'_'+protocol})
    SET usrv.name=p_name,usrv.port=port,usrv.protocol=protocol,
        usrv.product=p_product,usrv.version=p_version,
        usrv.etiqueta_visual=toString(port)+'/'+protocol
    MERGE (uh)-[:EXPONE_SERVICIO]->(usrv)
)
RETURN DISTINCT org,nSub,rSub,uh,relOrg,relRango,relHost`
    },
    {
        id: 'attackpath',
        title: "Camino de Ataque",
        needsExtra: null,
        query: `WITH 1 AS dummy
MATCH (o:ORIGEN)-[]-(h:HOST)
WHERE h.DISCOVERY_SOURCE STARTS WITH 'active'
  AND trim(toUpper(h.CRITICO)) IN ['SI','SÍ']
  AND h.ORGANIZACION = $org
WITH DISTINCT COALESCE(o.LOCATION,'Desconocido') AS loc, h.IP AS ip,
     max(h.MAC) AS p_mac, max(h.ORGANIZACION) AS p_org,
     max(h.SISTEMA) AS p_sistema, max(h.VENDOR) AS p_vendor,
     max(h.OS) AS p_os, max(h.HOSTNAME) AS p_hostname
MERGE (vh:riskmap_HostCritico {id: p_org+'_'+ip})
SET vh.IP=ip,vh.MAC=p_mac,vh.SISTEMA=p_sistema,vh.VENDOR=p_vendor,
    vh.OS=p_os,vh.HOSTNAME=p_hostname,vh.ORGANIZACION=p_org,vh.CRITICO='SI'
MERGE (vo:riskmap_Origen {id: p_org+'_'+ip+'_'+loc}) SET vo.name=loc
MERGE (vh)-[rel:ACCESIBLE_DESDE]->(vo)
RETURN vh,vo,rel`
    },
    {
        id: 'attacknode',
        title: "Nodo de Ataque",
        needsExtra: 'attack-target',
        // Dado un host objetivo (IP o hostname), pinta todos los orígenes
        // desde los que se ha alcanzado, junto con sus servicios expuestos.
        query: `WITH $target AS target
MATCH (h:HOST)
WHERE h.ORGANIZACION = $org
  AND (h.IP = target OR toLower(coalesce(h.HOSTNAME,'')) = toLower(target))
WITH $org AS org_key, h.IP AS ip,
     max(h.MAC) AS p_mac, max(h.HOSTNAME) AS p_hostname,
     max(h.SISTEMA) AS p_sistema, max(h.VENDOR) AS p_vendor,
     max(h.OS) AS p_os, max(h.CRITICO) AS p_critico,
     max(h.SUBRED) AS p_subred, max(h.NOMBRE_SUBRED) AS p_nsubred,
     max(h.ORGANIZACION) AS p_org
MERGE (ah:attackmap_HostObjetivo {id: org_key+'_'+ip})
SET ah.IP=ip, ah.MAC=p_mac, ah.HOSTNAME=p_hostname,
    ah.SISTEMA=p_sistema, ah.VENDOR=p_vendor, ah.OS=p_os,
    ah.CRITICO=p_critico, ah.SUBRED=p_subred,
    ah.NOMBRE_SUBRED=p_nsubred, ah.ORGANIZACION=p_org
WITH org_key, ip, ah
OPTIONAL MATCH (o:ORIGEN)-[]-(h:HOST {IP: ip})
WHERE h.ORGANIZACION = $org
WITH org_key, ah, ip, collect(DISTINCT COALESCE(o.LOCATION,'Desconocido')) AS locs
FOREACH (loc IN [x IN locs WHERE x IS NOT NULL] |
    MERGE (ao:attackmap_Origen {id: org_key+'_'+ah.IP+'_'+loc}) SET ao.name=loc
    MERGE (ao)-[:LLEGA_A]->(ah)
)
WITH org_key, ah, ip
OPTIONAL MATCH (h:HOST {IP: ip})-[]-(s:SERVICE)
WHERE h.ORGANIZACION = $org
WITH org_key, ah, ip, s.port AS port, s.protocol AS protocol,
     max(s.name) AS p_name, max(s.product) AS p_product,
     max(s.version) AS p_version, max(s.vulnerabilities) AS p_vuln
FOREACH (d IN CASE WHEN port IS NOT NULL THEN [1] ELSE [] END |
    MERGE (asrv:attackmap_Servicio {id: org_key+'_'+ip+'_'+toString(port)+'_'+protocol})
    SET asrv.port=port, asrv.protocol=protocol, asrv.name=p_name,
        asrv.product=p_product, asrv.version=p_version,
        asrv.vulnerabilities=p_vuln,
        asrv.etiqueta_visual=toString(port)+'/'+protocol
    MERGE (ah)-[:EXPONE_PUERTO]->(asrv)
)
WITH ah
OPTIONAL MATCH r1=(ao:attackmap_Origen)-[:LLEGA_A]->(ah)
OPTIONAL MATCH r2=(ah)-[:EXPONE_PUERTO]->(asrv:attackmap_Servicio)
RETURN ah, ao, asrv, r1, r2`
    }
];

// ──────────────────────────────────────────────────────────────────
// NODE STYLE MAP — emoji icon + color per label type
// All nodes render as circles (circularImage) with the emoji inside.
// ──────────────────────────────────────────────────────────────────
const NODE_STYLES = {
    // Raw Neo4j labels
    'HOST':             { emoji: '🖥️',  color: '#4ECDC4', size: 22 },
    'SERVICE':          { emoji: '⚙️',  color: '#FFE66D', size: 16 },
    'ORIGEN':           { emoji: '📡',  color: '#FF6B6B', size: 26 },
    'ORGANIZACION':     { emoji: '🏢',  color: '#a78bfa', size: 28 },
    'VULNERABILITY':    { emoji: '🐛',  color: '#f97316', size: 20 },
    'NETWORK':          { emoji: '🌐',  color: '#22c55e', size: 20 },
    // Structural labels from complex queries (matched by suffix after stripping prefix)
    'host':             { emoji: '🖥️',  color: '#4ECDC4', size: 22 },
    'hostunificado':    { emoji: '🖥️',  color: '#4ECDC4', size: 22 },
    'hostcritico':      { emoji: '⚠️',  color: '#ef4444', size: 24 },
    'servicio':         { emoji: '⚙️',  color: '#FFE66D', size: 16 },
    'serviceunificado': { emoji: '⚙️',  color: '#FFE66D', size: 16 },
    'origen':           { emoji: '📡',  color: '#FF6B6B', size: 26 },
    'organizacion':     { emoji: '🏢',  color: '#a78bfa', size: 28 },
    'nombredsubred':    { emoji: '🔗',  color: '#22c55e', size: 18 },
    'nombresubred':     { emoji: '🔗',  color: '#22c55e', size: 18 },
    'rangosubred':      { emoji: '📍',  color: '#16a34a', size: 16 },
    'hostobjetivo':     { emoji: '🎯',  color: '#ef4444', size: 30 },
};

const LEGEND_ITEMS = [
    { emoji: '🖥️', color: '#4ECDC4', label: 'Host' },
    { emoji: '⚙️', color: '#FFE66D', label: 'Servicio / Puerto' },
    { emoji: '📡', color: '#FF6B6B', label: 'Origen / Vector de escaneo' },
    { emoji: '🏢', color: '#a78bfa', label: 'Organización' },
    { emoji: '🐛', color: '#f97316', label: 'Vulnerabilidad' },
    { emoji: '🌐', color: '#22c55e', label: 'Subred / Red' },
    { emoji: '⚠️', color: '#ef4444', label: 'Host Crítico' },
    { emoji: '🎯', color: '#ef4444', label: 'Host Objetivo (Nodo de Ataque)' },
    { emoji: '🔗', color: '#22c55e', label: 'Nombre de subred' },
    { emoji: '📍', color: '#16a34a', label: 'Rango de subred' },
];

// ──────────────────────────────────────────────────────────────────
// STATE
// ──────────────────────────────────────────────────────────────────
let neoConfig       = null;   // { httpUrl, auth }
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
// NEO4J HTTP API
// ──────────────────────────────────────────────────────────────────
async function runCypher(cypher, params = {}) {
    if (!neoConfig) throw new Error('No hay configuración de Neo4j');

    const resp = await fetch(`${neoConfig.httpUrl}/db/neo4j/tx/commit`, {
        method: 'POST',
        headers: {
            'Authorization': neoConfig.auth,
            'Content-Type':  'application/json',
            'Accept':        'application/json',
            'X-Stream':      'true',
        },
        body: JSON.stringify({
            statements: [{
                statement:          cypher,
                parameters:         params,
                resultDataContents: ['row', 'graph'],
            }]
        }),
        signal: AbortSignal.timeout(20000),
    });

    if (!resp.ok) {
        const txt = await resp.text().catch(() => '');
        throw new Error(`HTTP ${resp.status} ${resp.statusText}: ${txt.substring(0, 200)}`);
    }

    const data = await resp.json();
    if (data.errors && data.errors.length > 0) {
        throw new Error(data.errors[0].message || JSON.stringify(data.errors[0]));
    }
    return data.results[0] || { columns: [], data: [] };
}

// ──────────────────────────────────────────────────────────────────
// NEO4J CONNECTION
// ──────────────────────────────────────────────────────────────────
async function autoConnect() {
    const cfg = window.NEO4J_CONFIG || {};
    const httpUrl  = cfg.httpUrl  || 'http://localhost:7474';
    const username = cfg.username || 'neo4j';
    const password = cfg.password || 'neo4j123';
    await connectToNeo4j(httpUrl, username, password);
}

async function connectToNeo4j(httpUrl, username, password) {
    setConnState('connecting', 'Conectando…');
    try {
        neoConfig = {
            httpUrl,
            auth: 'Basic ' + btoa(username + ':' + password),
        };
        await runCypher('RETURN 1 AS ok');
        isConnected = true;
        setConnState('connected', httpUrl.replace(/^https?:\/\//, ''));
        await fetchOrganizations();
    } catch (err) {
        isConnected = false;
        neoConfig = null;
        const msg = (err.message || String(err)).substring(0, 150);
        setConnState('disconnected', msg);
        console.error('[Graph] Connection error:', err);
    }
}

function setConnState(state, label) {
    document.getElementById('conn-dot').className    = 'conn-dot ' + state;
    document.getElementById('conn-label').textContent = label;
}

// ──────────────────────────────────────────────────────────────────
// ORGANIZATION SELECTOR
// ──────────────────────────────────────────────────────────────────
async function fetchOrganizations() {
    const sel = document.getElementById('org-select');
    sel.innerHTML = '<option value="">Cargando…</option>';
    sel.disabled  = true;

    try {
        const result = await runCypher(
            'MATCH (h:HOST) WHERE h.ORGANIZACION IS NOT NULL ' +
            'RETURN DISTINCT h.ORGANIZACION AS org ORDER BY org'
        );
        const orgs = result.data
            .map(d => d.row[0])
            .filter(Boolean);

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
        console.error('[Graph] fetchOrganizations:', e);
    }
}

function onOrgSelected(org) {
    selectedOrg = org || null;
    setLeftPanelState(!!org);

    // Reset extra controls — they're org-scoped
    const visOriginSel   = document.getElementById('visibility-origin-select');
    const attackTargetIn = document.getElementById('attack-target-input');
    if (visOriginSel) {
        visOriginSel.innerHTML = '<option value="">— Selecciona el origen —</option>';
        visOriginSel.disabled  = true;
    }
    if (attackTargetIn) attackTargetIn.value = '';

    // Re-evaluate the active preset so origins get re-fetched if needed
    const querySel = document.getElementById('query-select');
    if (querySel && querySel.value) querySel.dispatchEvent(new Event('change'));

    clearGraph();
    if (!org) return;

    execQuery(
        'MATCH (n)-[r]->(m) WHERE n.ORGANIZACION = $org OR m.ORGANIZACION = $org ' +
        'RETURN n,r,m LIMIT 120',
        true, { org }
    );
}

function setLeftPanelState(enabled) {
    document.getElementById('left-panel').classList.toggle('no-org', !enabled);
    // Run button gating is delegated to refreshRunButtonState() in bindEvents();
    // here we just disable when no org so the button can't fire pre-selection.
    if (!enabled) document.getElementById('run-query-btn').disabled = true;
}

// ──────────────────────────────────────────────────────────────────
// VISIBILITY-ORIGIN POPULATION
// Populates the #visibility-origin-select with the distinct ORIGEN
// locations that have active discovery records for the selected org.
// ──────────────────────────────────────────────────────────────────
async function populateOriginsForOrg(org) {
    const sel = document.getElementById('visibility-origin-select');
    if (!sel) return;
    sel.innerHTML = '<option value="">Cargando…</option>';
    sel.disabled  = true;

    if (!org || !isConnected) {
        sel.innerHTML = '<option value="">— Selecciona el origen —</option>';
        return;
    }
    try {
        const result = await runCypher(
            "MATCH (o:ORIGEN)-[]-(h:HOST) " +
            "WHERE h.ORGANIZACION = $org AND h.DISCOVERY_SOURCE STARTS WITH 'active' " +
            "RETURN DISTINCT COALESCE(o.LOCATION,'Desconocido') AS loc ORDER BY loc",
            { org }
        );
        const locs = (result.data || []).map(d => d.row[0]).filter(Boolean);
        sel.disabled = false;
        if (!locs.length) {
            sel.innerHTML = '<option value="">Sin orígenes activos</option>';
            return;
        }
        sel.innerHTML = '<option value="">— Selecciona el origen —</option>' +
            locs.map(l => `<option value="${escHtml(l)}">${escHtml(l)}</option>`).join('');
    } catch (e) {
        console.error('[Graph] populateOriginsForOrg:', e);
        sel.innerHTML = '<option value="">Error cargando orígenes</option>';
    }
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
        return (p.IP       && p.IP.toLowerCase().includes(lower))   ||
               (p.HOSTNAME && p.HOSTNAME.toLowerCase().includes(lower)) ||
               (p.name     && p.name.toLowerCase().includes(lower));
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
    if (!isConnected) return Promise.resolve();
    const trimmed = cypher.trim();
    if (!trimmed) return Promise.resolve();

    showOverlay(true, 'Ejecutando…');
    try {
        const result = await runCypher(trimmed, params);
        processResult(result, clearFirst);
    } catch(err) {
        console.error('[Graph] Query error:', err);
        showOverlay(false);
        alert('Error en la consulta:\n' + (err.message || String(err)));
    } finally {
        showOverlay(false);
    }
}

// ──────────────────────────────────────────────────────────────────
// RESULT PROCESSING  (HTTP API graph format)
// ──────────────────────────────────────────────────────────────────
function processResult(result, clearFirst) {
    const nodeMap  = new Map();
    const edgeMap  = new Map();
    let   hasGraph = false;
    const columns  = result.columns || [];
    const tabKeys  = [];
    const tabRows  = [];

    for (const item of (result.data || [])) {
        // Graph nodes + relationships
        if (item.graph) {
            if (item.graph.nodes.length > 0 || item.graph.relationships.length > 0) {
                hasGraph = true;
            }
            for (const node of item.graph.nodes) {
                collectNode(nodeMap, node);
            }
            for (const rel of item.graph.relationships) {
                collectEdge(edgeMap, rel);
            }
        }

        // Scalar / tabular rows
        if (!hasGraph && item.row) {
            const row = {};
            let hasScalar = false;
            for (let i = 0; i < columns.length; i++) {
                const val = item.row[i];
                if (val !== null && val !== undefined && typeof val !== 'object') {
                    row[columns[i]] = String(val);
                    hasScalar = true;
                    if (!tabKeys.includes(columns[i])) tabKeys.push(columns[i]);
                }
            }
            if (hasScalar) tabRows.push(row);
        }
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
// NODE / EDGE COLLECTION  (HTTP API format)
// ──────────────────────────────────────────────────────────────────
function getNodeStyle(labels) {
    for (const lbl of labels) {
        if (NODE_STYLES[lbl]) return NODE_STYLES[lbl];
    }
    for (const lbl of labels) {
        const base = lbl.replace(/^[a-z]+_/i, '').toLowerCase();
        if (NODE_STYLES[base]) return NODE_STYLES[base];
    }
    return { emoji: '❓', color: '#607080', size: 18 };
}

function collectNode(map, node) {
    // node = { id: "5", labels: [...], properties: {...} }
    const id = parseInt(node.id, 10);
    if (map.has(id)) return;
    if (!nodePassesOrgFilter(node.properties, node.labels)) return;

    const style = getNodeStyle(node.labels);
    const label = getNodeDisplayLabel(node.labels, node.properties);

    nodeTooltipData.set(id, { labels: node.labels, props: node.properties });

    const border   = darken(style.color, 45);
    const hlBorder = lighten(style.color, 20);

    map.set(id, {
        id,
        label,
        shape:       'circularImage',
        image:       makeIconDataUri(style.emoji, style.color),
        size:        style.size,
        borderWidth: 2,
        borderWidthSelected: 3,
        color: {
            border,
            background: style.color,
            highlight:  { border: hlBorder, background: style.color },
            hover:      { border: hlBorder, background: style.color },
        },
        _labels: node.labels,
        _props:  node.properties,
    });
}

function collectEdge(map, rel) {
    // rel = { id: "3", type: "...", startNode: "5", endNode: "6", properties: {...} }
    const id   = parseInt(rel.id, 10);
    const from = parseInt(rel.startNode, 10);
    const to   = parseInt(rel.endNode,   10);
    if (map.has(id)) return;
    edgeTooltipData.set(id, { type: rel.type, props: rel.properties || {} });
    map.set(id, {
        id,
        from,
        to,
        label:  rel.type,
        _type:  rel.type,
        _props: rel.properties || {},
    });
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
    div.innerHTML = LEGEND_ITEMS.map(item =>
        `<div class="legend-row">
            <span class="legend-icon" style="background:${item.color}">${item.emoji}</span>
            <span>${escHtml(item.label)}</span>
        </div>`
    ).join('');
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
    if (!isConnected || ids.length < 2) return;
    try {
        const result = await runCypher(
            'MATCH (a)-[r]->(b) WHERE id(a) IN $ids AND id(b) IN $ids RETURN r',
            { ids }
        );
        const edgeMap = new Map();
        for (const item of (result.data || [])) {
            for (const rel of (item.graph?.relationships || [])) {
                collectEdge(edgeMap, rel);
            }
        }
        const newEdges = [];
        for (const [id, e] of edgeMap) if (!edgesDS.get(id)) newEdges.push(e);
        if (newEdges.length) {
            edgesDS.add(newEdges);
            updateStats(nodesDS.length, edgesDS.length, null);
        }
    } catch(e) {
        console.warn('[Graph] fetchEdgesBetweenNodes:', e.message);
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
            'MATCH (n)-[r]-(m) WHERE id(n) = $nid RETURN n,r,m LIMIT 80',
            false,
            { nid: params.nodes[0] }
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
// EVENT BINDING
// ──────────────────────────────────────────────────────────────────
function bindEvents() {
    document.getElementById('reconnect-btn').addEventListener('click', () => {
        const cfg = window.NEO4J_CONFIG || {};
        connectToNeo4j(
            cfg.httpUrl  || 'http://localhost:7474',
            cfg.username || 'neo4j',
            cfg.password || 'neo4j123'
        );
    });

    const orgSel = document.getElementById('org-select');
    orgSel.addEventListener('change', () => onOrgSelected(orgSel.value));

    const searchInput = document.getElementById('node-search');
    const searchBtn   = document.getElementById('node-search-btn');
    searchInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') { clearTimeout(searchDebounce); searchNodes(searchInput.value); }
    });
    searchInput.addEventListener('input', () => {
        clearTimeout(searchDebounce);
        searchDebounce = setTimeout(() => searchNodes(searchInput.value), 350);
    });
    searchBtn.addEventListener('click', () => { clearTimeout(searchDebounce); searchNodes(searchInput.value); });

    const querySel        = document.getElementById('query-select');
    const visOriginSel    = document.getElementById('visibility-origin-select');
    const attackTargetIn  = document.getElementById('attack-target-input');
    const extraHint       = document.getElementById('query-extra-hint');

    function getActivePreset() {
        const idx = parseInt(querySel.value, 10);
        return (!isNaN(idx) && PRESET_QUERIES[idx]) ? PRESET_QUERIES[idx] : null;
    }

    function refreshRunButtonState() {
        const preset = getActivePreset();
        const baseEnabled = !!preset && !!selectedOrg;
        let extraOk = true;
        if (preset && preset.needsExtra === 'visibility-origin') {
            extraOk = !!visOriginSel.value;
        } else if (preset && preset.needsExtra === 'attack-target') {
            extraOk = !!attackTargetIn.value.trim();
        }
        document.getElementById('run-query-btn').disabled = !(baseEnabled && extraOk);
    }

    function setExtraVisibility(preset) {
        const showOrigin = preset && preset.needsExtra === 'visibility-origin';
        const showTarget = preset && preset.needsExtra === 'attack-target';
        visOriginSel.classList.toggle('hidden',   !showOrigin);
        attackTargetIn.classList.toggle('hidden', !showTarget);

        if (showOrigin) {
            extraHint.textContent = 'Selecciona el origen desde el que ver la visibilidad';
            populateOriginsForOrg(selectedOrg);
        } else if (showTarget) {
            extraHint.textContent = 'Indica IP o hostname del host objetivo';
            attackTargetIn.value = '';
        } else {
            extraHint.textContent = '';
        }
    }

    querySel.addEventListener('change', () => {
        setExtraVisibility(getActivePreset());
        refreshRunButtonState();
    });

    visOriginSel.addEventListener('change',   refreshRunButtonState);
    attackTargetIn.addEventListener('input',  refreshRunButtonState);

    document.getElementById('run-query-btn').addEventListener('click', () => {
        const preset = getActivePreset();
        if (!preset) return;
        const params = { org: selectedOrg || '' };
        if (preset.needsExtra === 'visibility-origin') {
            if (!visOriginSel.value) return;
            params.location = visOriginSel.value;
        } else if (preset.needsExtra === 'attack-target') {
            const t = attackTargetIn.value.trim();
            if (!t) return;
            params.target = t;
        }
        execQuery(preset.query, true, params);
    });

    document.getElementById('fit-btn').addEventListener('click',
        () => visNetwork.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } }));

    document.getElementById('clear-btn').addEventListener('click', clearGraph);

    document.getElementById('physics-toggle').addEventListener('change', e => {
        visNetwork.setOptions({ physics: { enabled: e.target.checked } });
    });

    document.getElementById('rp-close').addEventListener('click', hideRightPanel);
    document.getElementById('back-to-graph-btn').addEventListener('click', hideTableView);
}

// ──────────────────────────────────────────────────────────────────
// UTILITY
// ──────────────────────────────────────────────────────────────────
function escHtml(s) {
    return String(s ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function formatCellValue(v) {
    if (v === null || v === undefined) return '';
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
}

// Generates a square SVG data URI with a colored background and emoji centred.
// vis-network clips it to a circle via shape:'circularImage'.
function makeIconDataUri(emoji, bgColor) {
    const svg =
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">' +
        `<rect width="64" height="64" fill="${bgColor}"/>` +
        '<text x="32" y="32" font-size="34" text-anchor="middle" dominant-baseline="central" ' +
        'font-family="Apple Color Emoji,Segoe UI Emoji,Noto Color Emoji,sans-serif">' +
        emoji +
        '</text>' +
        '</svg>';
    return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
}

function darken(hex, amount) {
    const n = parseInt(hex.slice(1), 16);
    const r = Math.max(0, (n >> 16) - amount);
    const g = Math.max(0, ((n >> 8) & 0xFF) - amount);
    const b = Math.max(0, (n & 0xFF) - amount);
    return `#${((r<<16)|(g<<8)|b).toString(16).padStart(6,'0')}`;
}

function lighten(hex, amount) {
    const n = parseInt(hex.slice(1), 16);
    const r = Math.min(255, (n >> 16) + amount);
    const g = Math.min(255, ((n >> 8) & 0xFF) + amount);
    const b = Math.min(255, (n & 0xFF) + amount);
    return `#${((r<<16)|(g<<8)|b).toString(16).padStart(6,'0')}`;
}
