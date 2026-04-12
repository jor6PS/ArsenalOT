/* ================================================================
   ArsenalOT Graph Viewer — app.js
   Connects directly to Neo4j via the JavaScript Bolt driver,
   renders results with vis-network and shows properties in a
   BloodHound-style side panel.
   ================================================================ */

'use strict';

// ──────────────────────────────────────────────────────────────────
// PRESET QUERIES  — copia exacta de neo4j_queries.json
// ──────────────────────────────────────────────────────────────────
const PRESET_QUERIES = [
    {
        title: "🗺️ 1. Mapa de Visibilidad (Árboles independientes por Origen)",
        description: "Crea 'universos paralelos' para cada origen. Muestra qué redes, subredes, hosts y servicios ve cada escáner por separado.",
        query: `// ==========================================
// FASE 1: CREAR EL ÁRBOL INDEPENDIENTE POR ORIGEN (Origen -> Nombre -> Rango -> Host)
// ==========================================
MATCH (o:ORIGEN)-[]-(h:HOST)
WHERE h.DISCOVERY_SOURCE STARTS WITH 'active'

WITH COALESCE(o.LOCATION, 'Ubicación Desconocida') AS loc,
     h.NOMBRE_SUBRED AS nsub,
     h.SUBRED AS rsub,
     h.IP AS ip,
     max(h.ORGANIZACION) AS p_org,
     max(h.MAC) AS p_mac,
     max(h.SISTEMA) AS p_sistema,
     max(h.VENDOR) AS p_vendor,
     max(h.OS) AS p_os,
     max(h.CRITICO) AS p_critico,
     max(h.HOSTNAME) AS p_hostname

MERGE (vo:visibilitytest_Origen {name: loc})

MERGE (vnombre:visibilitytest_NombreSubred {id: loc + '_' + nsub})
SET vnombre.name = nsub
MERGE (vo)-[:visibilitytest_VE_RED]->(vnombre)

MERGE (vrango:visibilitytest_RangoSubred {id: loc + '_' + rsub})
SET vrango.rango = rsub
MERGE (vnombre)-[:visibilitytest_CONTIENE_RANGO]->(vrango)

MERGE (vh:visibilitytest_Host {id: loc + '_' + ip})
SET vh.IP = ip,
    vh.MAC = p_mac,
    vh.SISTEMA = p_sistema,
    vh.VENDOR = p_vendor,
    vh.OS = p_os,
    vh.CRITICO = p_critico,
    vh.HOSTNAME = p_hostname,
    vh.ORGANIZACION = p_org
MERGE (vrango)-[:visibilitytest_CONTIENE_HOST]->(vh)

// ==========================================
// FASE 2: UNIFICAR LOS SERVICIOS (EXCLUSIVOS POR ORIGEN Y HOST)
// ==========================================
WITH count(vh) AS barrera_1

MATCH (o:ORIGEN)-[]-(h:HOST)-[]-(s:SERVICE)
WHERE h.DISCOVERY_SOURCE STARTS WITH 'active'

WITH COALESCE(o.LOCATION, 'Ubicación Desconocida') AS loc,
     h.IP AS ip,
     s.port AS port,
     s.protocol AS protocol,
     max(s.name) AS p_name,
     max(s.product) AS p_product,
     max(s.version) AS p_version,
     max(s.vulnerabilities) AS p_vuln

MATCH (vh:visibilitytest_Host {id: loc + '_' + ip})

FOREACH (dummy IN CASE WHEN port IS NOT NULL THEN [1] ELSE [] END |
    MERGE (vsrv:visibilitytest_Servicio {id: loc + '_' + ip + '_' + toString(port) + '_' + protocol})
    SET vsrv.name = p_name,
        vsrv.port = port,
        vsrv.protocol = protocol,
        vsrv.product = p_product,
        vsrv.version = p_version,
        vsrv.vulnerabilities = p_vuln,
        vsrv.etiqueta_visual = toString(port) + '/' + protocol

    MERGE (vh)-[:visibilitytest_EXPONE_PUERTO]->(vsrv)
)

// ==========================================
// FASE 3: MOSTRAR SOLO LOS ORÍGENES EN PANTALLA
// ==========================================
WITH count(vh) AS barrera_2
MATCH (vo:visibilitytest_Origen)
RETURN DISTINCT vo`
    },
    {
        title: "🌐 2. Mapeo de Red Global (La Topología Absoluta)",
        description: "Unifica todos los datos en un único mapa maestro (Organización -> Nombre -> Rango -> Host).",
        query: `MATCH (h:HOST)
WHERE h.DISCOVERY_SOURCE STARTS WITH 'active'

WITH h.IP AS ip,
     max(h.ORGANIZACION) AS p_org,
     max(h.NOMBRE_SUBRED) AS p_nsub,
     max(h.SUBRED) AS p_rsub,
     max(h.MAC) AS p_mac,
     max(h.SISTEMA) AS p_sistema,
     max(h.VENDOR) AS p_vendor,
     max(h.OS) AS p_os,
     max(h.CRITICO) AS p_critico,
     max(h.HOSTNAME) AS p_hostname,
     max(h.DISCOVERY_SOURCE) AS p_disc

MERGE (org:networkmap_Organizacion {name: p_org})
MERGE (nSub:networkmap_NombreSubred {name: p_nsub})
MERGE (rSub:networkmap_RangoSubred {name: p_rsub})

MERGE (uh:networkmap_HostUnificado {IP: ip})
SET uh.MAC = p_mac,
    uh.SISTEMA = p_sistema,
    uh.VENDOR = p_vendor,
    uh.OS = p_os,
    uh.CRITICO = p_critico,
    uh.HOSTNAME = p_hostname,
    uh.DISCOVERY_SOURCE = p_disc,
    uh.ORGANIZACION = p_org,
    uh.NOMBRE_SUBRED = p_nsub,
    uh.SUBRED = p_rsub

MERGE (org)-[relOrg:networkmap_TIENE_SUBRED]->(nSub)
MERGE (nSub)-[relRango:networkmap_CONTIENE_RANGO]->(rSub)
MERGE (rSub)-[relHost:networkmap_TIENE_HOST]->(uh)

WITH org, nSub, rSub, uh, relOrg, relRango, relHost, ip

OPTIONAL MATCH (h:HOST {IP: ip})-[]-(s:SERVICE)
WHERE h.DISCOVERY_SOURCE STARTS WITH 'active' AND s IS NOT NULL

WITH org, nSub, rSub, uh, relOrg, relRango, relHost, ip,
     s.port AS port,
     s.protocol AS protocol,
     max(s.name) AS p_name,
     max(s.product) AS p_product,
     max(s.version) AS p_version,
     max(s.vulnerabilities) AS p_vuln

FOREACH (dummy IN CASE WHEN port IS NOT NULL THEN [1] ELSE [] END |
    MERGE (usrv:networkmap_ServiceUnificado {id: ip + '_' + toString(port) + '_' + protocol})
    SET usrv.name = p_name,
        usrv.port = port,
        usrv.protocol = protocol,
        usrv.product = p_product,
        usrv.version = p_version,
        usrv.vulnerabilities = p_vuln,
        usrv.etiqueta_visual = toString(port) + '/' + protocol

    MERGE (uh)-[:networkmap_EXPONE_SERVICIO]->(usrv)
)

RETURN DISTINCT org, nSub, rSub, uh, relOrg, relRango, relHost`
    },
    {
        title: "🚨 3. Camino de Ataque / Mapa de Riesgo",
        description: "Se centra en activos críticos, mostrando flechas directas desde los Orígenes que tienen alcance real.",
        query: `WITH 1 as dummy
MATCH (o:ORIGEN)-[]-(h:HOST)
WHERE h.DISCOVERY_SOURCE STARTS WITH 'active'
  AND trim(toUpper(h.CRITICO)) IN ['SI', 'SÍ']

WITH DISTINCT COALESCE(o.LOCATION, 'Ubicación Desconocida') AS loc,
     h.IP AS ip,
     max(h.MAC) AS p_mac,
     max(h.ORGANIZACION) AS p_org,
     max(h.SISTEMA) AS p_sistema,
     max(h.VENDOR) AS p_vendor,
     max(h.OS) AS p_os,
     max(h.HOSTNAME) AS p_hostname

// 1. Creamos el Host Crítico
MERGE (vh:riskmap_HostCritico {IP: ip})
SET vh.MAC = p_mac,
    vh.SISTEMA = p_sistema,
    vh.VENDOR = p_vendor,
    vh.OS = p_os,
    vh.HOSTNAME = p_hostname,
    vh.ORGANIZACION = p_org,
    vh.CRITICO = 'SI'

// 2. Creamos el Origen exclusivo para no crear telarañas
MERGE (vo:riskmap_Origen {id: ip + '_' + loc})
SET vo.name = loc

// 3. Trazamos la línea
MERGE (vh)-[rel:riskmap_ACCESIBLE_DESDE]->(vo)

// 4. Devolvemos los nodos y la relación
RETURN vh, vo, rel`
    },
    {
        title: "🔍 4. El Buscador Dinámico Unificado",
        description: "Busca una IP o rango CIDR, consolida duplicados y muestra un grafo limpio con orígenes y servicios.",
        query: `// 1. Escribe tu IP o tu Rango a buscar
WITH '10.239.148.209' AS busqueda

// 2. Extraemos la IP base y la máscara
WITH busqueda,
     split(busqueda, '/')[0] AS ip_base,
     toInteger(split(busqueda, '/')[1]) AS mascara
WITH busqueda, mascara, split(ip_base, '.') AS octetos

// 3. Calculamos el prefijo
WITH busqueda,
     CASE
       WHEN NOT busqueda CONTAINS '/' THEN busqueda
       WHEN mascara <= 8 THEN octetos[0] + '.'
       WHEN mascara <= 16 THEN octetos[0] + '.' + octetos[1] + '.'
       WHEN mascara <= 24 THEN octetos[0] + '.' + octetos[1] + '.' + octetos[2] + '.'
       ELSE octetos[0] + '.' + octetos[1] + '.' + octetos[2] + '.' + octetos[3]
     END AS filtro_ip

// ==========================================
// FASE 1: HOST CENTRAL
// ==========================================
MATCH (h:HOST)
WHERE (busqueda CONTAINS '/' AND h.IP STARTS WITH filtro_ip)
   OR (NOT busqueda CONTAINS '/' AND h.IP = filtro_ip)

WITH h.IP AS ip,
     max(h.MAC) AS p_mac,
     max(h.ORGANIZACION) AS p_org,
     max(h.SISTEMA) AS p_sistema,
     max(h.VENDOR) AS p_vendor,
     max(h.OS) AS p_os,
     max(h.CRITICO) AS p_critico,
     max(h.HOSTNAME) AS p_hostname

MERGE (sh:search_Host {IP: ip})
SET sh.MAC = p_mac,
    sh.ORGANIZACION = p_org,
    sh.SISTEMA = p_sistema,
    sh.VENDOR = p_vendor,
    sh.OS = p_os,
    sh.CRITICO = p_critico,
    sh.HOSTNAME = p_hostname

// ==========================================
// FASE 2: ORÍGENES REALES
// ==========================================
WITH sh, ip
OPTIONAL MATCH (o:ORIGEN)-[]-(h:HOST {IP: ip})
WITH sh, ip, collect(DISTINCT o.LOCATION) AS locs

FOREACH (loc IN [x IN locs WHERE x IS NOT NULL] |
    MERGE (so:search_Origen {name: loc})
    MERGE (so)-[:search_LLEGA_A]->(sh)
)

// ==========================================
// FASE 3: SERVICIOS CONSOLIDADOS
// ==========================================
WITH sh, ip
OPTIONAL MATCH (h:HOST {IP: ip})-[]-(s:SERVICE)
WITH sh, ip,
     s.port AS port,
     s.protocol AS protocol,
     max(s.name) AS p_name,
     max(s.vulnerabilities) AS p_vuln

FOREACH (dummy IN CASE WHEN port IS NOT NULL THEN [1] ELSE [] END |
    MERGE (ss:search_Servicio {id: ip + '_' + toString(port) + '_' + protocol})
    SET ss.name = p_name,
        ss.port = port,
        ss.protocol = protocol,
        ss.vulnerabilities = p_vuln,
        ss.etiqueta_visual = toString(port) + '/' + protocol

    MERGE (sh)-[:search_EXPONE_PUERTO]->(ss)
)

// ==========================================
// FASE 4: DIBUJAR PANTALLA
// ==========================================
WITH DISTINCT sh
OPTIONAL MATCH rel_o = (so:search_Origen)-[:search_LLEGA_A]->(sh)
OPTIONAL MATCH rel_s = (sh)-[:search_EXPONE_PUERTO]->(ss:search_Servicio)

RETURN sh, so, ss, rel_o, rel_s`
    },
    {
        title: "🧹 5. El Limpiador Definitivo (Borrar vistas personalizadas)",
        description: "Elimina de forma segura cualquier nodo temporal o vista generada, dejando la DB original intacta.",
        query: `MATCH (n)
WHERE ANY(label IN labels(n) WHERE
    label STARTS WITH 'search_' OR
    label STARTS WITH 'riskmap_' OR
    label STARTS WITH 'visibilitytest_' OR
    label STARTS WITH 'networkmap_'
)
DETACH DELETE n;`
    },
    {
        title: "🛡️ 6. Intersección de Criticidad y Vulnerabilidad",
        description: "Muestra los activos críticos que tienen servicios con vulnerabilidades conocidas (CVEs).",
        query: `MATCH (h:HOST)-[:HAS_SERVICE]->(s:SERVICE)
WHERE (trim(toUpper(h.CRITICO)) IN ['SI', 'SÍ']) AND s.vulnerabilities <> ""
RETURN h.IP AS Host, h.HOSTNAME AS Nombre, h.SISTEMA AS OS, s.port AS Puerto, s.name AS Servicio, s.vulnerabilities AS CVEs
ORDER BY h.IP`
    },
    {
        title: "🔌 7. Puertas Traseras y Gestión Expuesta",
        description: "Detecta servicios de administración remota (SSH, RDP, Telnet, VNC, HTTP/S) que podrían ser vectores de ataque.",
        query: `MATCH (h:HOST)-[:HAS_SERVICE]->(s:SERVICE)
WHERE s.port IN [21, 22, 23, 3389, 5900, 5901, 80, 443, 8080, 8443]
RETURN h.IP AS IP, s.port AS Puerto, s.name AS Protocolo, s.product AS Producto, h.CRITICO AS Es_Critico
ORDER BY s.port ASC`
    },
    {
        title: "🏭 8. Detección de Protocolos Industriales (OT Deep Dive)",
        description: "Identifica protocolos ICS/SCADA específicos (Modbus, S7, Ethernet/IP, Bacnet, MQTT, OPC UA, etc.).",
        query: `MATCH (h:HOST)-[:HAS_SERVICE]->(s:SERVICE)
WHERE s.port IN [102, 502, 2222, 44818, 47808, 1911, 20000, 1883, 8883, 4840]
   OR s.name CONTAINS 'modbus'
   OR s.name CONTAINS 's7'
   OR s.name CONTAINS 'enip'
   OR s.name CONTAINS 'mqtt'
   OR s.name CONTAINS 'opc'
RETURN h.IP AS IP, s.port AS Puerto, s.name AS Servicio, s.product AS Producto, s.version AS Version
ORDER BY IP`
    },
    {
        title: "📊 9. Concentración de Riesgo por Subred",
        description: "Calcula el número de vulnerabilidades acumuladas en cada segmento de red para priorizar el parcheo.",
        query: `MATCH (h:HOST)-[:HAS_SERVICE]->(s:SERVICE)
WHERE s.vulnerabilities <> ""
WITH h.SUBRED AS Subred, h.NOMBRE_SUBRED AS Nombre, count(s) AS Total_Vulns, collect(DISTINCT s.vulnerabilities) AS CVE_List
RETURN Subred, Nombre, Total_Vulns, CVE_List
ORDER BY Total_Vulns DESC`
    }
];

// ──────────────────────────────────────────────────────────────────
// COLOR PALETTE
// ──────────────────────────────────────────────────────────────────
const BASE_LABEL_COLORS = {
    'HOST':           '#4ECDC4',
    'SERVICE':        '#FFE66D',
    'ORIGEN':         '#FF6B6B',
    'ORGANIZACION':   '#7c3aed',
    'VULNERABILITY':  '#f97316',
    'NETWORK':        '#22c55e',
};

const DYNAMIC_PALETTE = [
    '#4ECDC4', '#FF6B6B', '#FFE66D', '#7c3aed', '#22c55e',
    '#f97316', '#06b6d4', '#ec4899', '#a78bfa', '#34d399',
    '#fb923c', '#60a5fa', '#f472b6', '#a3e635', '#2dd4bf',
    '#fbbf24', '#818cf8', '#f43f5e', '#10b981', '#3b82f6',
];

let labelColorMap  = {};
let colorIndex     = 0;

function labelToColor(label) {
    if (BASE_LABEL_COLORS[label]) return BASE_LABEL_COLORS[label];
    // Strip prefix like "networkmap_", "riskmap_", etc. and try again
    const base = label.replace(/^[a-z]+_/, '').toUpperCase();
    if (BASE_LABEL_COLORS[base]) return adjustHex(BASE_LABEL_COLORS[base], -25);
    if (labelColorMap[label])   return labelColorMap[label];
    const c = DYNAMIC_PALETTE[colorIndex % DYNAMIC_PALETTE.length];
    labelColorMap[label] = c;
    colorIndex++;
    return c;
}

// ──────────────────────────────────────────────────────────────────
// STATE
// ──────────────────────────────────────────────────────────────────
let neoDriver        = null;
let visNetwork       = null;
let nodesDS          = null;
let edgesDS          = null;
let isConnected      = false;
let activeQueryIdx   = -1;
let nodeTooltipData  = new Map();  // nodeId → { labels, props }
let edgeTooltipData  = new Map();  // edgeId → { type, props }

// ──────────────────────────────────────────────────────────────────
// BOOTSTRAP
// ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initVisNetwork();
    renderPresetList();
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
            shape: 'dot',
            size: 20,
            font: {
                size: 12,
                color: '#dde5f0',
                face: 'Segoe UI, system-ui, sans-serif',
                strokeWidth: 3,
                strokeColor: 'rgba(10,14,26,0.9)',
            },
            borderWidth: 2,
            borderWidthSelected: 3,
            shadow: { enabled: true, color: 'rgba(0,0,0,0.4)', size: 8, x: 2, y: 2 },
        },
        edges: {
            arrows: { to: { enabled: true, scaleFactor: 0.55, type: 'arrow' } },
            color: {
                color:     'rgba(78,205,196,0.28)',
                highlight: '#4ECDC4',
                hover:     'rgba(78,205,196,0.6)',
                inherit:   false,
            },
            font: {
                size: 10,
                color: '#5a7090',
                align: 'middle',
                background: 'rgba(10,14,26,0.75)',
            },
            smooth: { type: 'continuous', roundness: 0.15 },
            width: 1.5,
            selectionWidth: 2.5,
            hoverWidth: 2,
        },
        physics: {
            enabled: true,
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {
                gravitationalConstant: -65,
                centralGravity: 0.006,
                springLength: 130,
                springConstant: 0.04,
                avoidOverlap: 0.35,
                damping: 0.35,
            },
            // CRITICAL: disabled = no hidden freeze phase; graph is ALWAYS interactive
            stabilization: { enabled: false },
            minVelocity: 0.5,
        },
        interaction: {
            hover: true,
            tooltipDelay: 99999,   // safety — built-in tooltip disabled via no `title` on nodes
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

    // Custom tooltips
    visNetwork.on('hoverNode', function(params) {
        const data = nodeTooltipData.get(params.node);
        if (data) showCustomTooltip(data.labels, data.props, params.event);
    });
    visNetwork.on('blurNode',  function() { hideCustomTooltip(); });

    visNetwork.on('hoverEdge', function(params) {
        const data = edgeTooltipData.get(params.edge);
        if (data) showCustomTooltip([data.type], data.props, params.event);
    });
    visNetwork.on('blurEdge',  function() { hideCustomTooltip(); });
}

// ──────────────────────────────────────────────────────────────────
// NEO4J CONNECTION
// ──────────────────────────────────────────────────────────────────
async function autoConnect() {
    const cfg = window.NEO4J_CONFIG || {};
    const url  = cfg.boltUrl  || 'bolt://localhost:7687';
    const user = cfg.username || 'neo4j';
    const pass = cfg.password || 'neo4j123';
    await connectToNeo4j(url, user, pass);
}

async function connectToNeo4j(url, username, password) {
    setConnState('connecting', 'Conectando...');

    try {
        if (neoDriver) { try { await neoDriver.close(); } catch(_) {} neoDriver = null; }

        neoDriver = neo4j.driver(url, neo4j.auth.basic(username, password), {
            maxConnectionPoolSize: 5,
            connectionAcquisitionTimeout: 8000,
            disableLosslessIntegers: true,   // return JS numbers instead of Integer objects
        });

        await neoDriver.verifyConnectivity({ database: 'neo4j' });
        isConnected = true;
        setConnState('connected', 'Conectado a ' + url.replace('bolt://', ''));

        // Run default view on first connect
        await execQuery('MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 80', false);

    } catch (err) {
        isConnected = false;
        const msg = err.message ? err.message.substring(0, 100) : String(err);
        setConnState('disconnected', 'Error: ' + msg);
        console.error('[Graph Viewer] Connection error:', err);
    }
}

function setConnState(state, label) {
    const dot  = document.getElementById('conn-dot');
    const text = document.getElementById('conn-label');
    dot.className = 'conn-dot ' + state;
    text.textContent = label;
}

// ──────────────────────────────────────────────────────────────────
// QUERY EXECUTION
// ──────────────────────────────────────────────────────────────────
async function execQuery(cypher, clearFirst = true) {
    if (!neoDriver || !isConnected) {
        alert('No hay conexión activa con Neo4j.\nUsa el botón "↺ Reconectar".');
        return;
    }

    const trimmed = cypher.trim();
    if (!trimmed) return;

    showOverlay(true, 'Ejecutando consulta...');

    const session = neoDriver.session();
    try {
        const result = await session.run(trimmed);
        processRecords(result.records, clearFirst);
    } catch (err) {
        console.error('[Graph Viewer] Query error:', err);
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
    const nodeMap  = new Map();   // id → vis node obj
    const edgeMap  = new Map();   // id → vis edge obj
    let   hasGraph = false;

    const tabKeys = [];
    const tabRows = [];

    for (const rec of records) {
        const tabRow = {};
        let   rowHasScalar = false;

        for (const key of rec.keys) {
            const val = rec.get(key);
            if (val === null || val === undefined) { tabRow[key] = ''; rowHasScalar = true; continue; }

            if (neo4j.isNode(val)) {
                hasGraph = true;
                collectNode(nodeMap, val);
            } else if (neo4j.isRelationship(val)) {
                hasGraph = true;
                collectEdge(edgeMap, val);
            } else if (neo4j.isPath(val)) {
                hasGraph = true;
                collectPath(nodeMap, edgeMap, val);
            } else {
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

function collectNode(map, node) {
    const id = node.identity;
    if (map.has(id)) return;

    const primaryLabel = getPrimaryLabel(node.labels);
    const color        = labelToColor(primaryLabel);
    const label        = getNodeDisplayLabel(node.labels, node.properties);

    // Store tooltip data separately (not in DataSet — avoids vis rendering HTML as text)
    nodeTooltipData.set(id, { labels: node.labels, props: node.properties });

    map.set(id, {
        id,
        label,
        color: {
            background: color,
            border:     darken(color, 40),
            highlight:  { background: lighten(color, 25), border: color },
            hover:      { background: lighten(color, 15), border: color },
        },
        _labels:  node.labels,
        _props:   node.properties,
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
    if (clearFirst) {
        nodesDS.clear();
        edgesDS.clear();
        nodeTooltipData.clear();
        edgeTooltipData.clear();
        labelColorMap = {};
        colorIndex    = 0;
    }

    // Only add nodes/edges not already present
    const newNodes = [];
    const newEdges = [];

    for (const [id, node] of nodeMap) {
        if (!nodesDS.get(id)) newNodes.push(node);
    }
    for (const [id, edge] of edgeMap) {
        if (!edgesDS.get(id)) newEdges.push(edge);
    }

    nodesDS.add(newNodes);
    edgesDS.add(newEdges);

    updateStats(nodesDS.length, edgesDS.length, null);
    updateLegend();
    setEmptyState(nodesDS.length === 0);

    if (nodesDS.length > 0) {
        // Initial rough fit so nodes are visible while physics runs
        visNetwork.fit({ animation: false });

        // Fetch edges between visible nodes (Neo4j Browser behavior), then re-fit
        fetchEdgesBetweenNodes().then(() => {
            // Wait for physics to spread nodes before fitting cleanly
            setTimeout(() => {
                visNetwork.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
            }, 600);
        });
    }
}

// ──────────────────────────────────────────────────────────────────
// NODE / LABEL HELPERS
// ──────────────────────────────────────────────────────────────────
const PREFERRED_LABELS = ['HOST','SERVICE','ORIGEN','ORGANIZACION','VULNERABILITY','NETWORK'];

function getPrimaryLabel(labels) {
    if (!labels || labels.length === 0) return 'Node';
    for (const p of PREFERRED_LABELS) {
        if (labels.includes(p)) return p;
    }
    return labels[0];
}

const DISPLAY_PROP_PRIORITY = [
    'IP', 'name', 'HOSTNAME', 'port', 'LOCATION', 'ORGANIZACION',
    'etiqueta_visual', 'rango', 'id',
];

function getNodeDisplayLabel(labels, props) {
    for (const key of DISPLAY_PROP_PRIORITY) {
        if (props[key] !== undefined && props[key] !== null) {
            let v = String(props[key]);
            if (v.length > 22) v = v.substring(0, 20) + '…';
            return v;
        }
    }
    // fallback: use first non-null property
    for (const [, v] of Object.entries(props)) {
        if (v !== null && v !== undefined) {
            let s = String(v);
            if (s.length > 22) s = s.substring(0, 20) + '…';
            return s;
        }
    }
    return getPrimaryLabel(labels);
}

// ──────────────────────────────────────────────────────────────────
// CUSTOM TOOLTIP (replaces vis built-in to avoid rendering HTML as text)
// ──────────────────────────────────────────────────────────────────
function showCustomTooltip(labels, props, event) {
    const tt = document.getElementById('custom-tooltip');
    const MAX_PROPS = 10;
    const entries = Object.entries(props)
        .filter(([, v]) => v !== null && v !== undefined)
        .slice(0, MAX_PROPS);

    let html = `<div class="tt-label">${escHtml(labels.join(', '))}</div>`;
    for (const [k, v] of entries) {
        const disp = String(v).length > 70 ? String(v).substring(0, 68) + '…' : String(v);
        html += `<div class="tt-row">
                    <span class="tt-key">${escHtml(k)}</span>
                    <span class="tt-val">${escHtml(disp)}</span>
                 </div>`;
    }
    const total = Object.keys(props).length;
    if (total > MAX_PROPS) {
        html += `<div class="tt-more">+${total - MAX_PROPS} más...</div>`;
    }

    tt.innerHTML = html;
    tt.classList.remove('hidden');
    positionTooltip(tt, event);
}

function hideCustomTooltip() {
    document.getElementById('custom-tooltip').classList.add('hidden');
}

function positionTooltip(tt, event) {
    if (!event) return;
    const x  = event.clientX !== undefined ? event.clientX : (event.pageX || 0);
    const y  = event.clientY !== undefined ? event.clientY : (event.pageY || 0);
    const mx = 14;

    tt.style.left = (x + mx) + 'px';
    tt.style.top  = (y - mx) + 'px';

    // Keep inside viewport
    requestAnimationFrame(() => {
        const r = tt.getBoundingClientRect();
        if (r.right  > window.innerWidth  - 8) tt.style.left = (x - r.width  - mx) + 'px';
        if (r.bottom > window.innerHeight - 8) tt.style.top  = (y - r.height - mx) + 'px';
    });
}

// ──────────────────────────────────────────────────────────────────
// AUTO-FETCH EDGES BETWEEN VISIBLE NODES  (mirrors Neo4j Browser)
// ──────────────────────────────────────────────────────────────────
async function fetchEdgesBetweenNodes() {
    const ids = nodesDS.getIds();
    if (!neoDriver || !isConnected || ids.length < 2) return;

    const session = neoDriver.session();
    try {
        const result = await session.run(
            'MATCH (a)-[r]->(b) WHERE id(a) IN $ids AND id(b) IN $ids RETURN r',
            { ids }
        );
        const edgeMap = new Map();
        for (const rec of result.records) {
            const rel = rec.get('r');
            if (neo4j.isRelationship(rel)) collectEdge(edgeMap, rel);
        }
        const newEdges = [];
        for (const [id, edge] of edgeMap) {
            if (!edgesDS.get(id)) newEdges.push(edge);
        }
        if (newEdges.length > 0) {
            edgesDS.add(newEdges);
            updateStats(nodesDS.length, edgesDS.length, null);
        }
    } catch (e) {
        console.warn('[Graph Viewer] fetchEdgesBetweenNodes:', e.message);
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
        const nodeId = params.nodes[0];
        // Use Neo4j internal id — works for every node regardless of its properties
        execQuery(
            `MATCH (n)-[r]-(m) WHERE id(n) = ${nodeId} RETURN n, r, m LIMIT 100`,
            false   // append to current graph, don't clear
        );
    }
}

// ──────────────────────────────────────────────────────────────────
// RIGHT PANEL  — Node / Edge Properties
// ──────────────────────────────────────────────────────────────────
function showNodePanel(node) {
    const pill = document.getElementById('rp-type-pill');
    pill.textContent = 'Nodo';
    pill.className   = 'type-pill node';

    // Labels
    const labDiv = document.getElementById('rp-labels');
    labDiv.innerHTML = (node._labels || []).map(l => {
        const c = labelToColor(l);
        return `<span class="lbl-chip" style="border-color:${c}50;color:${c}">${l}</span>`;
    }).join('');

    // Properties
    renderPropList(node._props || {});

    // Context
    const neighbors = visNetwork.getConnectedNodes(node.id);
    const edges     = visNetwork.getConnectedEdges(node.id);
    document.getElementById('rp-context-text').textContent =
        `${neighbors.length} nodo(s) conectado(s) · ${edges.length} relación(es)`;

    openRightPanel();
}

function showEdgePanel(edge) {
    const pill = document.getElementById('rp-type-pill');
    pill.textContent = 'Relación';
    pill.className   = 'type-pill rel';

    const labDiv = document.getElementById('rp-labels');
    labDiv.innerHTML = `<span class="lbl-chip" style="color:#a78bfa;border-color:#7c3aed50">${edge._type || '?'}</span>`;

    renderPropList(edge._props || {});

    document.getElementById('rp-context-text').textContent =
        `De nodo ${edge.from} → nodo ${edge.to}`;

    openRightPanel();
}

function renderPropList(props) {
    const container = document.getElementById('rp-props');
    const entries   = Object.entries(props).filter(([, v]) => v !== null && v !== undefined);

    if (entries.length === 0) {
        container.innerHTML = '<div class="prop-entry"><span style="color:var(--text-dim);font-size:.78rem;">Sin propiedades</span></div>';
        return;
    }

    container.innerHTML = entries.map(([k, v]) =>
        `<div class="prop-entry">
            <div class="prop-k">${escHtml(k)}</div>
            <div class="prop-v">${escHtml(formatCellValue(v))}</div>
         </div>`
    ).join('');
}

function openRightPanel() {
    document.getElementById('right-panel').classList.remove('hidden');
}

function hideRightPanel() {
    document.getElementById('right-panel').classList.add('hidden');
}

// ──────────────────────────────────────────────────────────────────
// TABLE VIEW
// ──────────────────────────────────────────────────────────────────
function renderTable(keys, rows) {
    document.getElementById('table-label').textContent =
        `${rows.length} fila(s)`;

    const scroll = document.getElementById('table-scroll');
    let html = '<table><thead><tr>';
    html += keys.map(k => `<th>${escHtml(k)}</th>`).join('');
    html += '</tr></thead><tbody>';
    for (const row of rows) {
        html += '<tr>';
        html += keys.map(k => `<td>${escHtml(String(row[k] ?? ''))}</td>`).join('');
        html += '</tr>';
    }
    html += '</tbody></table>';
    scroll.innerHTML = html;

    document.getElementById('table-container').classList.remove('hidden');
    updateStats(0, 0, rows.length);
}

function hideTableView() {
    document.getElementById('table-container').classList.add('hidden');
}

// ──────────────────────────────────────────────────────────────────
// PRESET QUERY LIST
// ──────────────────────────────────────────────────────────────────
function renderPresetList(filter) {
    const wrap  = document.getElementById('query-list-wrap');
    const term  = (filter || '').toLowerCase();
    const items = PRESET_QUERIES.map((q, i) => {
        if (term && !q.title.toLowerCase().includes(term) &&
                    !q.description.toLowerCase().includes(term)) return '';
        return `<div class="query-item${activeQueryIdx === i ? ' active' : ''}"
                     data-idx="${i}"
                     onclick="handlePresetClick(${i})">
                    <div class="q-title">${escHtml(q.title)}</div>
                    <div class="q-desc">${escHtml(q.description)}</div>
                </div>`;
    }).join('');
    wrap.innerHTML = items || '<div style="padding:.5rem;color:var(--text-dim);font-size:.78rem;">Sin resultados</div>';
}

function handlePresetClick(idx) {
    activeQueryIdx = idx;
    renderPresetList(document.getElementById('query-search').value);
    const q = PRESET_QUERIES[idx];
    document.getElementById('custom-cypher').value = q.query;
    execQuery(q.query, true);
}

// ──────────────────────────────────────────────────────────────────
// LEGEND
// ──────────────────────────────────────────────────────────────────
function updateLegend() {
    const div    = document.getElementById('legend-items');
    const merged = { ...BASE_LABEL_COLORS, ...labelColorMap };
    div.innerHTML = Object.entries(merged).map(([lbl, color]) =>
        `<div class="legend-row">
            <span class="legend-dot" style="background:${color}"></span>
            <span>${escHtml(lbl)}</span>
         </div>`
    ).join('');
}

// ──────────────────────────────────────────────────────────────────
// UI HELPERS
// ──────────────────────────────────────────────────────────────────
function showOverlay(show, msg) {
    const el = document.getElementById('graph-overlay');
    if (show) {
        if (msg) document.getElementById('overlay-msg').textContent = msg;
        el.classList.remove('hidden');
    } else {
        el.classList.add('hidden');
    }
}

function setEmptyState(isEmpty) {
    const el = document.getElementById('graph-empty');
    if (isEmpty) el.classList.remove('hidden');
    else         el.classList.add('hidden');
}

function updateStats(nodes, edges, rows) {
    const el = document.getElementById('graph-stats');
    if (rows !== null && rows !== undefined) {
        el.textContent = `${rows} filas`;
    } else {
        el.textContent = `${nodes ?? nodesDS.length} nodos · ${edges ?? edgesDS.length} relaciones`;
    }
}

// ──────────────────────────────────────────────────────────────────
// EVENT BINDINGS
// ──────────────────────────────────────────────────────────────────
function bindEvents() {
    // Reconnect
    document.getElementById('reconnect-btn').addEventListener('click', autoConnect);

    // Run custom query
    document.getElementById('run-custom-btn').addEventListener('click', () => {
        const q = document.getElementById('custom-cypher').value.trim();
        if (q) { activeQueryIdx = -1; renderPresetList(); execQuery(q, true); }
    });

    // Ctrl+Enter in textarea
    document.getElementById('custom-cypher').addEventListener('keydown', e => {
        if (e.ctrlKey && e.key === 'Enter') {
            e.preventDefault();
            const q = e.target.value.trim();
            if (q) { activeQueryIdx = -1; renderPresetList(); execQuery(q, true); }
        }
    });

    // Clear graph
    document.getElementById('clear-btn').addEventListener('click', () => {
        nodesDS.clear();
        edgesDS.clear();
        nodeTooltipData.clear();
        edgeTooltipData.clear();
        labelColorMap = {};
        colorIndex    = 0;
        updateLegend();
        updateStats(0, 0, null);
        setEmptyState(true);
        hideRightPanel();
        hideCustomTooltip();
    });

    // Track mouse position to keep custom tooltip under cursor
    document.addEventListener('mousemove', e => {
        const tt = document.getElementById('custom-tooltip');
        if (!tt.classList.contains('hidden')) positionTooltip(tt, e);
    });

    // Fit graph
    document.getElementById('fit-btn').addEventListener('click', () => {
        if (visNetwork) visNetwork.fit({ animation: { duration: 350, easingFunction: 'easeInOutQuad' } });
    });

    // Physics toggle
    document.getElementById('physics-toggle').addEventListener('change', e => {
        if (visNetwork) visNetwork.setOptions({ physics: { enabled: e.target.checked } });
    });

    // Close right panel
    document.getElementById('rp-close').addEventListener('click', hideRightPanel);

    // Back to graph from table
    document.getElementById('back-to-graph-btn').addEventListener('click', hideTableView);

    // Search filter
    document.getElementById('query-search').addEventListener('input', e => {
        renderPresetList(e.target.value);
    });
}

// ──────────────────────────────────────────────────────────────────
// COLOR MATH HELPERS
// ──────────────────────────────────────────────────────────────────
function darken(hex, amount) { return adjustHex(hex, -Math.abs(amount)); }
function lighten(hex, amount){ return adjustHex(hex,  Math.abs(amount)); }

function adjustHex(hex, amt) {
    const n = parseInt((hex || '#888').replace('#', '').padEnd(6, '0'), 16);
    const r = Math.min(255, Math.max(0, (n >> 16)        + amt));
    const g = Math.min(255, Math.max(0, ((n >> 8) & 0xff)+ amt));
    const b = Math.min(255, Math.max(0, (n & 0xff)       + amt));
    return '#' + [r, g, b].map(v => v.toString(16).padStart(2, '0')).join('');
}

// ──────────────────────────────────────────────────────────────────
// VALUE FORMATTING
// ──────────────────────────────────────────────────────────────────
function formatCellValue(val) {
    if (val === null || val === undefined) return '';
    if (typeof val === 'object' && !Array.isArray(val)) {
        // neo4j Integer with disableLosslessIntegers=true → already a number
        // but handle edge cases
        if (typeof val.toNumber === 'function') return String(val.toNumber());
        return JSON.stringify(val);
    }
    if (Array.isArray(val)) return val.map(v => formatCellValue(v)).join(', ');
    return String(val);
}

function escHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
