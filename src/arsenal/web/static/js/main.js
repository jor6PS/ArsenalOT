// Utilidades generales

// ── Theme ─────────────────────────────────────────────────────────
const THEME_KEY = 'arsenal-theme';
const SIDEBAR_KEY = 'arsenal-sidebar';

// Las cargas GET de una pantalla no deben impedir salir a otra vista.
// Se abortan en el cliente al navegar; las operaciones POST (escaneos, imports,
// rellenado de bitácora, etc.) no se abortan para no dejar estados a medias.
(function initAbortablePageLoads() {
    const nativeFetch = window.fetch.bind(window);
    let pageLoadController = new AbortController();

    function abortPageLoads() {
        if (!pageLoadController.signal.aborted) {
            pageLoadController.abort();
        }
    }

    window.fetch = function arsenalFetch(input, options = {}) {
        const request = input instanceof Request ? input : null;
        const method = String(options.method || request?.method || 'GET').toUpperCase();
        if (method === 'GET' && !options.signal) {
            options = { ...options, signal: pageLoadController.signal };
        }
        return nativeFetch(input, options);
    };

    window.addEventListener('beforeunload', abortPageLoads);
    document.addEventListener('click', (event) => {
        const link = event.target.closest?.('a[href]');
        if (!link || link.target || event.defaultPrevented || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        const url = new URL(link.href, window.location.href);
        if (url.origin === window.location.origin && url.href !== window.location.href) {
            abortPageLoads();
        }
    }, { capture: true });
})();

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_KEY, theme);
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    applyTheme(current === 'dark' ? 'light' : 'dark');
}

function forcedThemeFromUrl() {
    const theme = new URLSearchParams(window.location.search).get('theme');
    return theme === 'light' || theme === 'dark' ? theme : null;
}

// ── Sidebar ───────────────────────────────────────────────────────
function setSidebarCollapsed(collapsed) {
    const sidebar = document.getElementById('sidebar');
    const sidebarW = collapsed ? 'var(--sidebar-w-collapsed)' : '260px';
    if (!sidebar) return;
    if (collapsed) {
        sidebar.classList.add('is-collapsed');
    } else {
        sidebar.classList.remove('is-collapsed');
    }
    document.documentElement.style.setProperty('--sidebar-w', collapsed ? '68px' : '260px');
    localStorage.setItem(SIDEBAR_KEY, collapsed ? 'collapsed' : 'expanded');
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;
    const isCollapsed = sidebar.classList.contains('is-collapsed');
    setSidebarCollapsed(!isCollapsed);
}

// ── Sidebar groups ────────────────────────────────────────────────
function sidebarGroupToggle(groupId) {
    const group = document.getElementById(groupId);
    if (!group) return;
    group.classList.toggle('is-open');
}

// ── Init ──────────────────────────────────────────────────────────
(function initArsenalUI() {
    // Apply forced URL theme for capture/export pages, otherwise saved theme.
    const savedTheme = forcedThemeFromUrl() || localStorage.getItem(THEME_KEY) || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);

    // Apply saved sidebar state
    const savedSidebar = localStorage.getItem(SIDEBAR_KEY);
    if (savedSidebar === 'collapsed') {
        setSidebarCollapsed(true);
    }

    // Bind theme toggle
    const themeBtn = document.getElementById('themeToggle');
    if (themeBtn) themeBtn.addEventListener('click', toggleTheme);

    // Bind sidebar toggle
    const sidebarBtn = document.getElementById('sidebarToggle');
    if (sidebarBtn) sidebarBtn.addEventListener('click', toggleSidebar);

    // Mobile: close sidebar when clicking outside
    document.addEventListener('click', (e) => {
        const sidebar = document.getElementById('sidebar');
        if (!sidebar) return;
        if (window.innerWidth <= 768 && sidebar.classList.contains('is-mobile-open')) {
            if (!sidebar.contains(e.target)) {
                sidebar.classList.remove('is-mobile-open');
            }
        }
    });
})();

// Formatear fechas
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('es-ES');
}

// Mostrar notificaciones
function showNotification(message, type = 'info') {
    // Crear elemento de notificación
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#2563eb'};
        color: white;
        border-radius: 4px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        z-index: 1000;
        animation: slideIn 0.3s ease-out;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Agregar estilos de animación
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// Manejar errores de fetch
async function safeFetch(url, options = {}) {
    try {
        const response = await fetch(url, options);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Fetch error:', error);
        showNotification('Error de conexión: ' + error.message, 'error');
        throw error;
    }
}
