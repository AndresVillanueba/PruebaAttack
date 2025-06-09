// Funciones principales para el panel de administración
document.addEventListener('DOMContentLoaded', function() {
  // Verificar si el usuario está autenticado y es admin
  const token = localStorage.getItem('token');
  const role = localStorage.getItem('role');
  
  if (!token || role !== 'admin') {
    window.location.href = 'index.html';
    return;
  }
  
  // Inicializar componentes
  initAdminSearch();
  loadAdminAnalyses();
  loadUsers();
  
  // Inicializar eventos de tabs
  initTabEvents();
});

// Inicializar eventos de búsqueda
function initAdminSearch() {
  // Formulario de búsqueda
  document.getElementById('admin-search-form').addEventListener('submit', function(e) {
    e.preventDefault();
    loadAdminAnalyses();
  });
    // Botón de limpiar filtros
  document.getElementById('clear-admin-filters').addEventListener('click', function() {
    document.getElementById('filter-user').value = '';
    document.getElementById('filter-type').value = '';
    document.getElementById('filter-target').value = '';
    document.getElementById('filter-from').value = '';
    document.getElementById('filter-to').value = '';
    
    // Ocultar notificación de filtrado
    const notificationEl = document.getElementById('admin-notifications');
    if (notificationEl) {
      notificationEl.style.display = 'none';
    }
    
    loadAdminAnalyses();
  });
  
  // Botón de limpiar filtros de usuarios
  document.getElementById('clear-user-filters').addEventListener('click', function() {
    document.getElementById('filter-username').value = '';
    
    // Ocultar notificación si existe
    const notificationEl = document.getElementById('user-notifications');
    if (notificationEl) {
      notificationEl.style.display = 'none';
    }
    
    // Renderizar usuarios sin filtros
    if (typeof renderUsers === 'function') {
      renderUsers();
    }
  });
  
  // Botón de actualizar
  document.getElementById('refresh-admin-analyses').addEventListener('click', function() {
    // Eliminar botones de "volver" que pudieran existir
    document.querySelectorAll('.btn.btn-secondary.mt-3.mb-3').forEach(btn => {
      btn.remove();
    });
    loadAdminAnalyses();
  });
}

// Inicializar eventos de tabs
function initTabEvents() {
  // Cambiar a pestaña de análisis
  document.getElementById('analyses-tab').addEventListener('click', function() {
    loadAdminAnalyses();
  });
  
  // Cambiar a pestaña de usuarios
  document.getElementById('users-tab').addEventListener('click', function() {
    loadUsers();
  });
}

// Mostrar notificación en el panel admin
function showAdminNotification(section, type, message) {
  const notificationEl = document.getElementById(`${section}-notifications`);
  if (!notificationEl) return;
  
  notificationEl.className = `alert alert-${type}`;
  notificationEl.textContent = message;
  notificationEl.style.display = 'block';
  
  // Solo ocultar automáticamente para mensajes de éxito y error, mantener los informativos visibles
  if (type !== 'info') {
    setTimeout(() => {
      notificationEl.style.display = 'none';
    }, 5000);
  }
}