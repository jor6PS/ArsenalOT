// ArsenalOT - JavaScript principal

// Utilidades generales
const Utils = {
    formatDate: (dateString) => {
        const date = new Date(dateString);
        return date.toLocaleString('es-ES');
    },
    
    formatBytes: (bytes) => {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    },
    
    showNotification: (message, type = 'info') => {
        // Crear notificación toast
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#3b82f6'};
            color: white;
            border-radius: 5px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            z-index: 3000;
            animation: slideIn 0.3s ease;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }
};

// Añadir estilos de animación
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

// Manejo de errores global
window.addEventListener('error', (e) => {
    console.error('Error global:', e);
    Utils.showNotification('Ha ocurrido un error inesperado', 'error');
});

// Manejo de errores de fetch
const originalFetch = window.fetch;
window.fetch = async function(...args) {
    try {
        const response = await originalFetch(...args);
        if (!response.ok && response.status >= 500) {
            Utils.showNotification('Error del servidor. Por favor, intenta de nuevo.', 'error');
        }
        return response;
    } catch (error) {
        Utils.showNotification('Error de conexión. Verifica tu conexión a internet.', 'error');
        throw error;
    }
};

// Exportar para uso global
window.Utils = Utils;

