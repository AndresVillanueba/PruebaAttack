$(function () {
  const API_BASE = '';

  // Cachés de elementos
  const $form   = $('#analysis-form');
  const $table  = $('#results-table');
  const $tbody  = $('#results-output');
  const $full   = $('#full-report');
  const $wrap   = $('#results');
  const $btnPDF = $('#download-report');
  const $loginSection = $('#login-section');
  const $mainContent  = $('#main-content');
  const $historyBtn   = $('#show-history');
  const $historySec   = $('#history-section');
  const $historyOut   = $('#history-output');
  const $loadingBar   = $('#loading-bar');
  const $closeHistory = $('#close-history');
  const $startAnalysis = $('#start-analysis-btn');

  // Transición suave entre login y main-content
  function showMainContent() {
    $('#login-section').addClass('fade-out').removeClass('fade-in');
    setTimeout(() => {
      $('#login-section').hide();
      $('#main-content').show().addClass('fade-in').removeClass('fade-out');
      $('#logout-btn').addClass('show').removeClass('d-none');
      $('#help-btn').addClass('d-none'); // Oculta el help de la navbar tras login
      $('#help-btn-form').removeClass('d-none'); // Muestra el help del form
      $('body').addClass('logged-in');
      $('#login-section').remove();
      mostrarUsuarioNavbar();
      // Al mostrar el main-content, asegurar que el historial está cerrado
      $historySec.hide();
      $closeHistory.removeClass('show').hide();
      $historyBtn.show();
    }, 400);
  }
  function showLogin() {
    $('#main-content').addClass('fade-out').removeClass('fade-in');
    setTimeout(() => {
      $('#main-content').hide();
      $('#login-section').show().addClass('fade-in').removeClass('fade-out');
      $('#logout-btn').removeClass('show').addClass('d-none');
      $('#help-btn').removeClass('d-none'); // Muestra el help de la navbar en login
      $('#help-btn-form').addClass('d-none'); // Oculta el help del form
      $('body').removeClass('logged-in');
      // Limpiar formularios y errores
      $('#login-form')[0].reset();
      $('#register-form')[0].reset();
      $('#login-error').hide();
      $('#register-error').hide();
      $('#register-success').hide();
    }, 400);
  }

  // Mostrar nombre de usuario en la barra superior si está logueado
  function mostrarUsuarioNavbar() {
    const username = localStorage.getItem('username');
    if (username) {
      $('#user-display').text(username).show();
    } else {
      $('#user-display').hide();
    }
  }

  // Login
  $('#login-form').submit(async function(e) {
    e.preventDefault();
    const username = $('#username').val();
    const password = $('#password').val();
    $('#login-error').hide();
    try {
      const resp = await $.ajax({
        url: `${API_BASE}/api/login`,
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ username, password })
      });
      if (resp.token) {
        showMainContent();
        localStorage.setItem('token', resp.token);
        localStorage.setItem('username', username); // Guardar nombre de usuario
        $.ajaxSetup({
          headers: { 'Authorization': 'Bearer ' + resp.token }
        });
      } else {
        $('#login-error').text('Usuario o contraseña incorrectos').fadeIn();
      }
    } catch (err) {
      $('#login-error').text('Usuario o contraseña incorrectos').fadeIn();
    }
  });

  $('#username, #password').on('input', function() {
    $('#login-error').fadeOut();
  });

  // Logout
  $('#logout-btn').click(function() {
    localStorage.removeItem('token');
    localStorage.removeItem('username'); // Eliminar nombre de usuario
    // Recarga la página para restaurar el login-section eliminado
    location.reload();
  });

  // --- Barra de progreso animada con tiempo real ---
  let loadingInterval = null;
  let loadingStart = null;
  function startLoadingBarReal() {
    loadingStart = Date.now();
    let percent = 0;
    const $bar = $('#loading-bar-inner');
    $bar.css('width', '0%').text(`Cargando análisis... (0 s)`);
    $('#loading-bar').show();
    loadingInterval = setInterval(() => {
      const elapsed = Math.floor((Date.now() - loadingStart) / 1000);
      percent = (percent + 3) % 100; // animación indefinida
      $bar.css('width', percent + '%');
      $bar.text(`Cargando análisis... (${elapsed} s)`);
    }, 1000);
  }
  function stopLoadingBarReal() {
    clearInterval(loadingInterval);
    $('#loading-bar').hide();
    $('#loading-bar-inner').css('width', '0%').text('Cargando análisis...');
  }

  // Configuración global de AJAX para incluir el token si existe
  const token = localStorage.getItem('token');
  if (token) {
    $.ajaxSetup({
      headers: { 'Authorization': 'Bearer ' + token }
    });
  }

  // Mostrar historial al iniciar sesión o al pulsar el botón
  async function mostrarHistorial() {
    try {
      const resp = await $.ajax({
        url: `${API_BASE}/api/history`,
        type: 'GET',
        headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
      });
      $historyOut.empty();
      let results = resp.history || resp.results || [];
      if (results.length === 0) {
        $historySec.hide();
        $closeHistory.removeClass('show').hide();
        return;
      }
      // Mostrar filas y guardar resumen en data
      results.forEach((r, idx) => {
        $historyOut.append(`
          <tr class="history-row" data-idx="${idx}">
            <td>${new Date(r.timestamp).toLocaleString()}</td>
            <td>${r.target}</td>
            <td>${r.analyzer}</td>
          </tr>
        `);
      });
      $historySec.show();
      $closeHistory.addClass('show').show();
      $historyBtn.hide();
      // Al hacer clic en una fila, NO mostrar resumen debajo
      $('.history-row').off('click').on('click', function() {
        // No hacer nada, no mostrar resumen
      });
      // Limpiar resumen al cerrar historial
      $closeHistory.off('click').on('click', function() {
        $historySec.hide();
        $closeHistory.removeClass('show').hide();
        $historyBtn.show();
        $('#history-summary').remove();
      });
    } catch (err) {
      $historySec.hide();
      $closeHistory.removeClass('show').hide();
    }
  }

  // Mostrar historial al hacer login
  $(document).on('showMainContent', mostrarHistorial);
  // Mostrar historial al pulsar el botón
  $historyBtn.click(mostrarHistorial);

  // Descargar PDF solo del análisis mostrado
  let lastAnalysisTimestamp = null;

  // Lanzar análisis
  $form.on('submit', async function (e) {
    e.preventDefault();
    const target       = $('#target').val().trim();
    const analysisType = $('#analysis-type').val();
    startLoadingBarReal();
    $wrap.hide();
    $tbody.empty();
    $full.empty();
    $btnPDF.hide();
    $startAnalysis.prop('disabled', true);
    try {
      const resp = await $.ajax({
        url:  `${API_BASE}/api/analyze`,
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ target, analysisType }),
        headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
      });
      // Guardar el timestamp del análisis actual para el PDF
      lastAnalysisTimestamp = resp.timestamp || (resp.full && resp.full.timestamp) || null;
      // Mostrar informe AI arriba
      if (resp.resumenAI) {
        $full.text(resp.resumenAI).show();
      } else if (resp.aiReport) {
        $full.text(resp.aiReport).show();
      } else if (resp.full) {
        $full.text(typeof resp.full === 'string' ? resp.full : JSON.stringify(resp.full, null, 2)).show();
      } else {
        $full.text('No se generó informe AI').show();
      }
      // Pintar tabla de resultados
      $tbody.empty();
      if (resp.results && resp.results.length) {
        resp.results.forEach(r => {
          let desc = r.description || '-';
          let service = r.service || '-';

          // --- Enriquecimiento de identificadores de vulnerabilidad/exploit ---
          let idType = null, idValue = null, link = null, icon = null, tooltip = null, nvdLink = null, extraLinks = [];
          let normalized = service.toString().trim();

          // CVE
          let cveMatch = normalized.match(/^(CVE-\d{4}-\d{4,})$/i);
          if (!cveMatch) cveMatch = normalized.match(/NUCLEI:(CVE-\d{4}-\d{4,})/i);
          if (!cveMatch) cveMatch = normalized.match(/OSV:(CVE-\d{4}-\d{4,})/i);
          if (!cveMatch) cveMatch = normalized.match(/DEBIANCVE:(CVE-\d{4}-\d{4,})/i);
          if (cveMatch) {
            idType = 'CVE';
            idValue = cveMatch[1].toUpperCase();
            link = `https://www.cve.org/CVERecord?id=${idValue}`;
            nvdLink = `https://nvd.nist.gov/vuln/detail/${idValue}`;
            icon = '<i class="fa-solid fa-bug text-danger" style="margin-right:4px;" title="CVE"></i>';
            tooltip = 'Common Vulnerabilities and Exposures (CVE)';
            extraLinks.push(`<a href="${nvdLink}" target="_blank" rel="noopener noreferrer">NVD</a>`);
          }

          // Exploit-DB
          let edbMatch = normalized.match(/^(EDB-ID[-:]?\d+)/i);
          if (!idType && edbMatch) {
            idType = 'EDB';
            idValue = edbMatch[1].replace(/EDB-ID[-:]?/i, '');
            link = `https://www.exploit-db.com/exploits/${idValue}`;
            icon = '<i class="fa-solid fa-bolt text-warning" style="margin-right:4px;" title="Exploit-DB"></i>';
            tooltip = 'Exploit Database (Exploit-DB)';
          }

          // 1337DAY
          let day1337Match = normalized.match(/^(1337DAY[-:]?\d+)/i);
          if (!idType && day1337Match) {
            idType = '1337DAY';
            idValue = day1337Match[1].replace(/1337DAY[-:]?/i, '');
            link = `https://1337day.com/exploit/${idValue}`;
            icon = '<i class="fa-solid fa-skull-crossbones text-dark" style="margin-right:4px;" title="1337DAY"></i>';
            tooltip = '1337DAY Exploit';
          }

          // PacketStorm
          let packetstormMatch = normalized.match(/^(PACKETSTORM[-:]?\d+)/i);
          if (!idType && packetstormMatch) {
            idType = 'PACKETSTORM';
            idValue = packetstormMatch[1].replace(/PACKETSTORM[-:]?/i, '');
            link = `https://packetstormsecurity.com/files/${idValue}/`;
            icon = '<i class="fa-solid fa-cloud-bolt text-info" style="margin-right:4px;" title="PacketStorm"></i>';
            tooltip = 'PacketStorm Security';
          }

          // Kitploit
          let kitploitMatch = normalized.match(/^(KITPLOIT[-:]?\d+)/i);
          if (!idType && kitploitMatch) {
            idType = 'KITPLOIT';
            idValue = kitploitMatch[1].replace(/KITPLOIT[-:]?/i, '');
            link = `https://www.kitploit.com/search?q=${idValue}`;
            icon = '<i class="fa-solid fa-toolbox text-secondary" style="margin-right:4px;" title="Kitploit"></i>';
            tooltip = 'Kitploit';
          }

          // ZSL (Zero Science Lab)
          let zslMatch = normalized.match(/^(ZSL[-:]?\d+)/i);
          if (!idType && zslMatch) {
            idType = 'ZSL';
            idValue = zslMatch[1].replace(/ZSL[-:]?/i, '');
            link = `https://www.zeroscience.mk/en/vulnerabilities/ZSL-${idValue}.php`;
            icon = '<i class="fa-solid fa-flask text-success" style="margin-right:4px;" title="Zero Science Lab"></i>';
            tooltip = 'Zero Science Lab';
          }

          // OSV (Open Source Vulnerabilities)
          let osvMatch = normalized.match(/^(OSV[-:]?\w+)/i);
          if (!idType && osvMatch) {
            idType = 'OSV';
            idValue = osvMatch[1].replace(/OSV[-:]?/i, '');
            link = `https://osv.dev/vulnerability/${idValue}`;
            icon = '<i class="fa-solid fa-code-branch text-primary" style="margin-right:4px;" title="OSV"></i>';
            tooltip = 'Open Source Vulnerabilities (OSV)';
          }

          // RHSA (Red Hat Security Advisory)
          let rhsaMatch = normalized.match(/^(RHSA-\d{4}:\d+)/i);
          if (!idType && rhsaMatch) {
            idType = 'RHSA';
            idValue = rhsaMatch[1];
            link = `https://access.redhat.com/errata/${idValue}`;
            icon = '<i class="fa-solid fa-hat-cowboy text-danger" style="margin-right:4px;" title="Red Hat Advisory"></i>';
            tooltip = 'Red Hat Security Advisory';
          }

          // Debian CVE
          let debianCveMatch = normalized.match(/^(DEBIANCVE:(CVE-\d{4}-\d{4,}))/i);
          if (!idType && debianCveMatch) {
            idType = 'DEBIANCVE';
            idValue = debianCveMatch[1].replace('DEBIANCVE:', '');
            link = `https://security-tracker.debian.org/tracker/${idValue}`;
            icon = '<i class="fa-brands fa-debian text-danger" style="margin-right:4px;" title="Debian CVE"></i>';
            tooltip = 'Debian Security Tracker';
          }

          // Si se detectó tipo, enriquecer la celda
          if (idType && link && link.indexOf('undefined') === -1 && link.trim() !== '' && !/\/$/.test(link)) {
            service = `<span class=\"vuln-id\" data-toggle=\"tooltip\" title=\"${tooltip}\">${icon}<a href=\"${link}\" target=\"_blank\" rel=\"noopener noreferrer\">${idType}${idValue ? (idType==='CVE'?'':'-')+idValue : ''}</a></span>`;
            if (idType === 'CVE' && nvdLink) {
              service += ` <a href=\"${nvdLink}\" target=\"_blank\" rel=\"noopener noreferrer\" title=\"Ver en NVD\"><i class=\"fa-solid fa-arrow-up-right-from-square text-secondary\"></i></a>`;
            }
            // Descripción específica por tipo
            if (idType === 'CVE') {
              desc = `Vulnerabilidad pública. Consulta la ficha oficial en <a href=\"${link}\" target=\"_blank\" rel=\"noopener noreferrer\">cve.org</a> o <a href=\"${nvdLink}\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a>.`;
            } else if (idType === 'EDB') {
              desc = `Exploit público en Exploit-DB. <a href=\"${link}\" target=\"_blank\" rel=\"noopener noreferrer\">Ver exploit</a>.`;
            } else if (idType === '1337DAY') {
              desc = `Exploit público en 1337DAY. <a href=\"${link}\" target=\"_blank\" rel=\"noopener noreferrer\">Ver exploit</a>.`;
            } else if (idType === 'PACKETSTORM') {
              desc = `Exploit o PoC en PacketStorm. <a href=\"${link}\" target=\"_blank\" rel=\"noopener noreferrer\">Ver recurso</a>.`;
            } else if (idType === 'KITPLOIT') {
              desc = `Herramienta o exploit en Kitploit. <a href=\"${link}\" target=\"_blank\" rel=\"noopener noreferrer\">Buscar en Kitploit</a>.`;
            } else if (idType === 'ZSL') {
              desc = `Vulnerabilidad publicada en Zero Science Lab. <a href=\"${link}\" target=\"_blank\" rel=\"noopener noreferrer\">Ver detalle</a>.`;
            } else if (idType === 'OSV') {
              desc = `Vulnerabilidad en Open Source Vulnerabilities. <a href=\"${link}\" target=\"_blank\" rel=\"noopener noreferrer\">Ver ficha</a>.`;
            } else if (idType === 'RHSA') {
              desc = `Aviso de seguridad de Red Hat. <a href=\"${link}\" target=\"_blank\" rel=\"noopener noreferrer\">Ver advisory</a>.`;
            } else if (idType === 'DEBIANCVE') {
              desc = `Vulnerabilidad rastreada por Debian. <a href=\"${link}\" target=\"_blank\" rel=\"noopener noreferrer\">Ver tracker</a>.`;
            }
          } else if ((idType && (!link || link.indexOf('undefined') !== -1 || link.trim() === '' || /\/$/.test(link))) || /^[A-Za-z0-9_-]{6,}$/.test(normalized)) {
            // Si el tipo es conocido pero la URL está vacía/no válida, o es una cadena alfanumérica larga, mostrar como identificador interno/desconocido
            service = `<span class=\"vuln-id\" data-toggle=\"tooltip\" title=\"Identificador interno o desconocido\"><i class=\"fa-solid fa-circle-info text-muted" style="margin-right:4px;"></i>${normalized}</span>`;
            desc = 'Identificador interno, UUID o referencia no estándar detectada por la herramienta. Puede ser un ID de base de datos, PoC, o referencia interna.';
          }

          // Si la descripción es del tipo "Dirígete a este CVE: <url>"
          const match = desc.match(/^Dirígete a este CVE: (https?:\/\/\S+)/);
          if (match) {
            desc = `<a href="${match[1]}" target="_blank" rel="noopener noreferrer">Dirígete a este CVE</a>`;
          }

          $tbody.append(`
            <tr>
              <td>${service}</td>
              <td>${desc}</td>
            </tr>
          `);
        });
      } else {
        $tbody.append('<tr><td colspan="2">Sin resultados</td></tr>');
      }
      $wrap.fadeIn();
      $btnPDF.show();
      stopLoadingBarReal();
      mostrarHistorial(); // Refresca historial tras análisis
    } catch (err) {
      if (err.status === 401 && err.responseJSON && (err.responseJSON.error === 'Token requerido' || err.responseJSON.error === 'Token inválido')) {
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        location.reload();
        return;
      }
      const msg = err.responseJSON?.error || err.statusText || err.message || 'Error desconocido';
      alert(`Error al ejecutar el análisis:\n${msg}`);
      stopLoadingBarReal();
    } finally {
      $startAnalysis.prop('disabled', false);
    }
  });

  $btnPDF.off('click').on('click', function(e) {
    e.preventDefault();
    const token = localStorage.getItem('token');
    if (!token) {
      alert('Debes iniciar sesión para descargar el informe.');
      return;
    }
    if (!lastAnalysisTimestamp) {
      alert('No hay análisis para descargar.');
      return;
    }
    fetch(`/api/download-report/${lastAnalysisTimestamp}`, {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    })
      .then(response => {
        if (!response.ok) return response.json().then(data => { throw new Error(data.error || 'No se pudo descargar el informe.'); });
        return response.blob();
      })
      .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'informe.pdf';
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      })
      .catch(err => {
        alert('Error al descargar el informe PDF. ' + (err.message || ''));
      });
  });

  // Mostrar historial con filtro de fechas (filtrado en backend)
  $historyBtn.click(async function() {
    try {
      const from = $('#history-from').val();
      const to = $('#history-to').val();
      let url = `${API_BASE}/api/history`;
      const params = [];
      if (from) params.push(`from=${from}`);
      if (to) params.push(`to=${to}`);
      if (params.length) url += '?' + params.join('&');
      const resp = await $.ajax({
        url,
        type: 'GET',
        headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
      });
      $historyOut.empty();
      let results = resp.history || resp.results || [];
      if (results.length === 0) {
        $historySec.hide();
        $closeHistory.removeClass('show').hide();
        alert('No hay historial disponible para ese filtro.');
        return;
      }
      results.forEach(r => {
        $historyOut.append(`
          <tr>
            <td>${new Date(r.timestamp).toLocaleString()}</td>
            <td>${r.target}</td>
            <td>${r.analyzer}</td>
          </tr>
        `);
      });
      $historySec.show();
      $closeHistory.addClass('show').show();
      $historyBtn.hide(); // Oculta 'Ver Historial' cuando se muestra el historial
    } catch (err) {
      alert('Error cargando historial');
    }
  });

  $closeHistory.click(function() {
    $historySec.hide();
    $closeHistory.removeClass('show').hide();
    $historyBtn.show(); // Vuelve a mostrar 'Ver Historial' al cerrar
  });

  // Filtrar historial al enviar el formulario
  $('#history-filter-form').submit(function(e) {
    e.preventDefault();
    $historyBtn.click();
  });
  $('#clear-history-filter').click(function() {
    $('#history-from').val('');
    $('#history-to').val('');
    $historyBtn.click();
  });

  // Mostrar modal de ayuda
  $('#help-btn').click(function() {
    $('#help-modal').modal('show');
  });
  $('#help-btn-form').click(function() {
    $('#help-modal').modal('show');
  });
  $('#help-btn-form-top').click(function() {
    $('#help-modal').modal('show');
  });

  // Alternar entre login y registro
  $('#show-register').click(function(e) {
    e.preventDefault();
    $('#login-form').hide();
    $('#register-form').show();
    $('#login-error').hide();
  });
  $('#show-login').click(function(e) {
    e.preventDefault();
    $('#register-form').hide();
    $('#login-form').show();
    $('#register-error').hide();
    $('#register-success').hide();
  });

  // Registro de usuario
  $('#register-form').submit(async function(e) {
    e.preventDefault();
    const username = $('#reg-username').val().trim();
    const password = $('#reg-password').val();
    $('#register-error').hide();
    $('#register-success').hide();
    if (username.toLowerCase() === 'admin') {
      $('#register-error').text('No puedes registrar el usuario admin.').fadeIn();
      return;
    }
    try {
      const resp = await $.ajax({
        url: '/api/register',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ username, password })
      });
      if (resp.success) {
        $('#register-success').text('Usuario creado correctamente. Ahora puedes iniciar sesión.').fadeIn();
        setTimeout(() => {
          $('#register-form').hide();
          $('#login-form').show();
          $('#register-success').hide();
        }, 1500);
      }
    } catch (err) {
      const msg = err.responseJSON?.error || 'Error al registrar usuario';
      $('#register-error').text(msg).fadeIn();
    }
  });

  // --- BLOQUEO DE ACCESO SIN LOGIN (frontend) ---
  function isLoggedIn() {
    const token = localStorage.getItem('token');
    if (!token) return false;
    // Validación rápida: JWT tiene 3 partes y no está vacío
    if (token.split('.').length !== 3) return false;
    // Opcional: comprobar expiración (sin decodificar en backend)
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      if (payload.exp && Date.now() / 1000 > payload.exp) return false;
      return true;
    } catch { return false; }
  }

  function forceLoginIfNotLogged() {
    if (!isLoggedIn()) {
      showLogin();
      $('#main-content').hide();
      $('#logout-btn').removeClass('show').addClass('d-none');
      // Limpia posibles datos sensibles
      $form[0].reset();
      $tbody.empty();
      $full.empty();
      $wrap.hide();
      $btnPDF.hide();
      $historySec.hide();
    }
  }

  // Al cargar la página, forzar login si no autenticado
  forceLoginIfNotLogged();

  // Al cargar la página, si hay token y username en localStorage, mostrar main content directamente
  if (isLoggedIn()) {
    showMainContent();
  }

  // Proteger acciones críticas
  $form.on('submit', function(e) {
    if (!isLoggedIn()) {
      e.preventDefault();
      forceLoginIfNotLogged();
      return false;
    }
  });
  $btnPDF.on('click', function(e) {
    if (!isLoggedIn()) {
      e.preventDefault();
      forceLoginIfNotLogged();
      return false;
    }
  });
  $historyBtn.on('click', function(e) {
    if (!isLoggedIn()) {
      e.preventDefault();
      forceLoginIfNotLogged();
      return false;
    }
  });
  $('#history-filter-form').on('submit', function(e) {
    if (!isLoggedIn()) {
      e.preventDefault();
      forceLoginIfNotLogged();
      return false;
    }
  });

  // Mostrar el informe solo si hay contenido y el usuario está logueado
  function mostrarInformeCompleto(texto) {
    if (isLoggedIn() && texto && texto.trim().length > 0) {
      $('#full-report').text(texto).show();
    } else {
      $('#full-report').hide();
    }
  }

  // Cuando recibas el informe de Ollama, llama a mostrarInformeCompleto
  // Ejemplo:
  // mostrarInformeCompleto(respuestaOllama);
});

// Al cargar la página, ocultar el help del form por defecto
$('#help-btn-form').addClass('d-none');