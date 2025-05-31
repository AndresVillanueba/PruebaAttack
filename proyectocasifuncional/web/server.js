require('dotenv').config();
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012'; // 32 chars para AES-256
const express = require('express');
const path    = require('path');
const axios   = require('axios');
const { Client } = require('@opensearch-project/opensearch');
const jwt = require('jsonwebtoken');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app        = express();
const PORT       = process.env.PORT || 8080;
const CORTEX_URL = process.env.CORTEX_URL || 'http://localhost:9001';
const API_KEY    = process.env.CORTEX_API_KEY;
const OPENSEARCH_HOST = 'http://localhost:9200';
const INDEX_NAME = 'analisis';

/* Configuración Ollama  */
const OLLAMA_PORT  = process.env.OLLAMA_PORT  || 11434;   // puerto por defecto: 11434
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'llama3'; 

/* Cliente OpenSearch */
const searchClient = new Client({ node: OPENSEARCH_HOST });

async function checkIndex () {
  try {
    const { body: exists } = await searchClient.indices.exists({ index: INDEX_NAME });
    if (!exists) {
      console.log('No se ha encontrado el índice, creando...');
      const { body: response } = await searchClient.indices.create({
        index: INDEX_NAME,
        body: {
          settings: {
            number_of_replicas: 1,
            number_of_shards:   1
          }
        }
      });
      return response;
    }
  } catch (error) {
    console.log('Error obteniendo datos de OpenSearch', error);
  }
}

async function checkUserIndex() {
  try {
    const { body: exists } = await searchClient.indices.exists({ index: 'usuarios' });
    if (!exists) {
      console.log('No se ha encontrado el índice de usuarios, creando...');
      await searchClient.indices.create({
        index: 'usuarios',
        body: {
          settings: {
            number_of_replicas: 1,
            number_of_shards: 1
          },
          mappings: {
            properties: {
              username: { type: 'keyword' },
              password: { type: 'keyword' },
              role: { type: 'keyword' },
              googleId: { type: 'keyword' }
            }
          }
        }
      });
    }
  } catch (error) {
    console.log('Error comprobando/creando índice de usuarios', error);
  }
}

if (!API_KEY) console.warn('CORTEX_API_KEY no está definido; la web no podrá llamar a Cortex');

app.use(express.static(path.join(__dirname)));
app.use(express.json());


/*  Mapa de analizadores disponibles */
const cfgMap = {
  attack_surface_scan: {
    name:  'SmapScan_1_0',
    type:  'other',
    build: t => t.trim()
  },
  cve_lookup: {
    name:  'Vulners_CVE_1_0',
    type:  'cve',
    build: t => t.trim().toUpperCase(),
    validate: txt => /^CVE-\d{4}-\d{4,}$/i.test(txt)
  },
  subdomain_enum: {
    name:  'Crt_sh_Transparency_Logs_1_0',
    type:  'domain',
    build: t => t.trim().toLowerCase()
  },
};

/* Utilidades Cortex */
const cortexHeaders = { Authorization: `Bearer ${API_KEY}` };

async function resolveWorkerId (analyzerName) {
  const { data } = await axios.get(`${CORTEX_URL}/api/analyzer`, { headers: cortexHeaders });
  const found = data.find(a => a.name === analyzerName);
  return found?.id ?? null;
}

// Añadir soporte de idioma a Ollama y robustecer historial y PDF
async function generateOllamaReport (report, lang = 'es') {
  const url = `http://localhost:${OLLAMA_PORT}/api/generate`;
  // PROMPT MEJORADO: pide idioma y formato
  let idioma = 'español';
  if (lang === 'en') idioma = 'inglés';
  else if (lang === 'fr') idioma = 'francés';
  else if (lang === 'pt') idioma = 'portugués';
  // Puedes añadir más idiomas si lo deseas
  const prompt =
    `Eres un analista de ciberseguridad. Responde SIEMPRE en ${idioma}. Analiza el siguiente resultado técnico y realiza dos tareas:\n` +
    `1. Extrae y lista de forma clara y concisa los siguientes elementos si existen: puertos abiertos (formato: puerto/protocolo), subdominios detectados, CVEs relevantes, exploits destacados.\n` +
    `2. Después, redacta un informe ejecutivo breve (máx. 150 palabras) para un cliente no técnico, destacando riesgos clave, impacto y siguientes pasos.\n` +
    `\nDatos técnicos:\n${JSON.stringify(report, null, 2)}\n\n` +
    `Primero la lista técnica, luego el informe ejecutivo.\n`;
  const payload = { model: OLLAMA_MODEL, prompt, stream: false };
  try {
    const response = await axios({ method: 'post', url, data: payload, responseType: 'json' });
    return response.data.response || response.data;
  } catch (err) {
    console.error('Error llamando a Ollama', err.message);
    return 'No se pudo generar el informe AI';
  }
}

// Tabla de usuarios en OpenSearch
async function saveUserToDB(user) {
  // Usar el username como _id para evitar duplicados y permitir upsert
  await searchClient.index({
    index: 'usuarios',
    id: user.username, // <--- clave: usar username como id
    body: {
      username: user.username,
      password: user.password, // hashed o vacío para Google
      role: user.role,
      googleId: user.googleId || null
    },
    refresh: 'true'
  });
}

async function getUserFromDB(username) {
  const { body } = await searchClient.search({
    index: 'usuarios',
    body: { query: { term: { username } } },
    size: 1
  });
  if (body.hits.hits.length > 0) return body.hits.hits[0]._source;
  return null;
}

// Guardar reportes desencriptados en OpenSearch
async function saveReport (doc) {
  try {
    // No guardar el informe de Ollama (aiReport) en OpenSearch, solo los datos originales
    const { aiReport, ...docSinAI } = doc;
    const encryptedDoc = encrypt(JSON.stringify(docSinAI));
    // Extract key fields for indexing
    const { username, analyzer, timestamp, role, target } = docSinAI;
    const res = await searchClient.index({
      index: INDEX_NAME,
      body: {
        username,
        analyzer,
        timestamp,
        role,
        target,
        data: encryptedDoc
      },
      refresh: 'true'
    });
    return res;
  } catch (error) {
    console.log('Error añadiendo a OpenSearch:', error && (error.body || error.message || error));
    throw error;
  }
}

// Leer reportes desencriptados
async function getDecryptedReports(query, size = 100) {
  const { body } = await searchClient.search({
    index: INDEX_NAME,
    size,
    body: { query, sort: [{ timestamp: { order: 'desc' } }] }
  });
  const hits = body.hits?.hits || [];
  return hits.map(hit => {
    try {
      return JSON.parse(decrypt(hit._source.data));
    } catch {
      return null;
    }
  }).filter(Boolean);
}

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const USERS_FILE = path.join(__dirname, 'users.json');

function readUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function generateToken(user) {
  return jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer '))
    return res.status(401).json({ error: 'Token requerido' });
  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  const textParts = text.split(':');
  const iv = Buffer.from(textParts.shift(), 'hex');
  const encryptedText = Buffer.from(textParts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

// Registro de usuario
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, error: 'Faltan datos' });
  if (username.toLowerCase() === 'admin') return res.status(400).json({ success: false, error: 'No puedes registrar el usuario admin.' });
  const users = readUsers();
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ success: false, error: 'Usuario ya existe' });
  }
  const hashed = await bcrypt.hash(password, 10);
  const userObj = { username, password: hashed, role: 'user' };
  users.push(userObj);
  writeUsers(users);
  await saveUserToDB(userObj);
  res.json({ success: true });
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  let user = await getUserFromDB(username);
  if (!user) {
    // fallback: users.json
    const users = readUsers();
    user = users.find(u => u.username === username);
  }
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Credenciales incorrectas' });
  const token = generateToken(user);
  res.json({ token, role: user.role });
});

app.post('/api/analyze', authMiddleware, async (req, res) => {
  await checkIndex();
  const { target, analysisType, lang } = req.body;
  let cfg = cfgMap[analysisType];
  console.log(`[ANALYZE] Inicio análisis: type=${analysisType}, target=${target}, lang=${lang}`);
  // --- NUEVO: Si el análisis es cve_lookup y el target NO es un CVE, buscar CVEs para el dominio/IP ---
  if (analysisType === 'cve_lookup' && !/^CVE-\d{4}-\d{4,}$/i.test(target)) {
    try {
      // 1. Resolver IP si es dominio
      let ip = target;
      if (!/^\d+\.\d+\.\d+\.\d+$/.test(target)) {
        const dns = require('dns').promises;
        try {
          console.log(`[CVE_LOOKUP] Resolviendo dominio: ${target}`);
          const addresses = await dns.lookup(target);
          ip = addresses.address;
          console.log(`[CVE_LOOKUP] IP resuelta: ${ip}`);
        } catch (dnsErr) {
          console.error('[CVE_LOOKUP] Error resolviendo dominio:', dnsErr.message);
          return res.status(400).json({ analyzer: 'Vulners_CVE_1_0', results: [{ service: '-', description: 'No se pudo resolver el dominio a IP', details: dnsErr.message }], full: {}, resumenAI: '' });
        }
      }
      // 2. Consultar Vulners API para buscar CVEs asociadas a esa IP o dominio
      let vulns = [];
      let vulnersResp = null;
      let vulnersLuceneResp = null;
      let vulnersIOCResp = null;
      let vulnersError = null;
      let triedIOC = false;
      let iocType = 'ip';
      let iocValue = ip;
      if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(target) && !/^\d+\.\d+\.\d+\.\d+$/.test(target)) {
        iocType = 'domain';
        iocValue = target;
      } else if (/^https?:\/\//.test(target)) {
        iocType = 'url';
        iocValue = target;
      }
      // --- Mejor gestión de errores y fallback ---
      if (process.env.VULNERS_API_KEY) {
        try {
          console.log(`[CVE_LOOKUP] Consultando Vulners IOC: type=${iocType}, value=${iocValue}`);
          vulnersIOCResp = await axios.post('https://vulners.com/api/v3/ioc/search/', {
            [iocType]: iocValue
          }, {
            headers: { 'Content-Type': 'application/json', 'Api-Key': process.env.VULNERS_API_KEY }
          });
          triedIOC = true;
          console.log('[CVE_LOOKUP] Respuesta Vulners IOC:', JSON.stringify(vulnersIOCResp.data, null, 2));
          if (Array.isArray(vulnersIOCResp.data.data?.results) && vulnersIOCResp.data.data.results.length > 0) {
            vulns = vulnersIOCResp.data.data.results.map(r => ({
              id: r.ioc_url || '-',
              title: r.fp_descr || r.ioc_result || '-',
              description: r.tags ? r.tags.join(', ') : '-',
              details: `First seen: ${r.first_seen || '-'} | Last seen: ${r.last_seen || '-'}`
            }));
          }
        } catch (iocErr) {
          // Si es 404, solo loguea y sigue con Lucene
          if (iocErr.response && iocErr.response.status === 404) {
            console.warn('[CVE_LOOKUP] Vulners IOC 404: No hay datos para', iocType, iocValue);
          } else {
            vulnersError = iocErr.response?.data?.error || iocErr.message;
            console.error('[CVE_LOOKUP] Error consultando Vulners IOC:', vulnersError);
          }
        }
      }
      // Fallback: si no hay vulns, intentar Lucene con el valor original (dominio o IP)
      if (vulns.length === 0) {
        try {
          console.log(`[CVE_LOOKUP] Consultando Vulners Lucene: query=${iocValue}`);
          vulnersLuceneResp = await axios.get('https://vulners.com/api/v3/search/lucene/', {
            params: { query: iocValue, size: 50 }
          });
          console.log('[CVE_LOOKUP] Respuesta Vulners Lucene:', JSON.stringify(vulnersLuceneResp.data, null, 2));
          if (Array.isArray(vulnersLuceneResp.data.data?.search)) {
            vulns = vulnersLuceneResp.data.data.search.map(r => ({
              id: r.id || r._id || '-',
              title: r.title || '-',
              description: r.description || '-',
              cvss: r.cvss || {},
              url: r.href || r.url || '',
              references: r.references || [],
              published: r.published || '',
              lastseen: r.lastseen || ''
            }));
          }
        } catch (luceneErr) {
          console.error('[CVE_LOOKUP] Error consultando Vulners Lucene:', luceneErr.message);
        }
      }
      // 3. Si no se encontraron CVEs, devolver mensaje adecuado
      let rows = [];
      // Añadir CVEs (de Vulners, Lucene o Shodan)
      if (vulns.length > 0) {
        console.log(`[CVE_LOOKUP] CVEs/Exploits encontrados: ${vulns.length}`);
        rows = vulns.map(v => ({
          service: v.id || v.cve || '-',
          description: (typeof v.flatDescription === 'string' && v.flatDescription.trim() && v.flatDescription !== '-' && !/^detalles descripción/i.test(v.flatDescription)) ? v.flatDescription
            : (typeof v.title === 'string' && v.title.trim() && v.title !== '-' && !/^detalles descripción/i.test(v.title) ? v.title
            : (typeof v.description === 'string' && v.description.trim() && v.description !== '-' && !/^detalles descripción/i.test(v.description) ? v.description
            : 'Esto es un CVE: Common Vulnerability. Consulta la web oficial: https://www.cve.org/')),
          details: [
            v.cvss && v.cvss.score ? `CVSS: ${v.cvss.score}` : '',
            v.cvss && v.cvss.vector ? `Vector: ${v.cvss.vector}` : '',
            v.references && v.references.length ? `Referencias: ${(Array.isArray(v.references) ? v.references.filter(Boolean).join(', ') : v.references)}` : '',
            v.published ? `Publicado: ${v.published}` : '',
            v.lastseen ? `Última vez visto: ${v.lastseen}` : ''
          ].filter(Boolean).join(' | ')
        }));
      }
      // Si el resultado de Vulners trae exploits en report.full.exploits, devolverlos como exploits y no como CVEs vacíos
      let exploits = [];
      if (vulnersResp && vulnersResp.data && vulnersResp.data.data && vulnersResp.data.data.full && Array.isArray(vulnersResp.data.data.full.exploits)) {
        exploits = vulnersResp.data.data.full.exploits.map(e => ({
          service: 'Exploit',
          title: e.title || '-',
          description: e.title || '-',
          published: e.published || '',
          url: e.url || ''
        }));
      }
      // Si hay exploits, añadirlos a los resultados
      if (exploits.length > 0) {
        console.log(`[CVE_LOOKUP] Exploits adicionales encontrados: ${exploits.length}`);
        rows = rows.concat(exploits.map(e => ({
          service: e.service,
          description: e.title,
          details: [e.published ? `Publicado: ${e.published}` : '', e.url ? `URL: ${e.url}` : ''].filter(Boolean).join(' | ')
        })));
      }
      // Si hay exploits y no hay CVEs válidos, mostrar solo exploits
      if (rows.length === 0 && exploits.length > 0) {
        rows = exploits.map(e => ({
          service: e.service,
          description: e.title,
          details: [e.published ? `Publicado: ${e.published}` : '', e.url ? `URL: ${e.url}` : ''].filter(Boolean).join(' | ')
        }));
      }
      // --- Generar informe AI con Ollama y adjuntar al resultado ---
      let resumenAI = '';
      try {
        // Para el informe AI, pasar el array de vulns (y exploits si hay) como contexto
        const aiInput = { vulns, exploits };
        resumenAI = await generateOllamaReport(aiInput, lang || 'es');
        console.log('[CVE_LOOKUP] Resumen AI generado:', resumenAI);
      } catch (ollamaErr) {
        console.error('[CVE_LOOKUP] Error generando informe AI:', ollamaErr.message);
      }
      // Al devolver el resultado, incluir el objeto completo de Vulners en 'full' para el informe AI y PDF
      let fullResult = {};
      if (vulnersResp && vulnersResp.data && vulnersResp.data.data) {
        fullResult = vulnersResp.data.data;
        console.log('[ANALYZE] Vulners full result:', JSON.stringify(fullResult, null, 2)); // LOG DEL RESULTADO VULNERS
      }
      // Guardar el análisis de CVEs en OpenSearch ANTES de responder
      const doc = {
        timestamp: new Date().toISOString(),
        target,
        analyzer: 'cve_lookup',
        result: { results: rows, full: fullResult },
        username: req.user.username,
        role: req.user.role
      };
      console.log('[CVE_LOOKUP] Intentando guardar análisis en OpenSearch:', JSON.stringify(doc, null, 2));
      try {
        await saveReport(doc);
        console.log('[CVE_LOOKUP] Guardado en OpenSearch OK');
      } catch (saveErr) {
        console.error('[CVE_LOOKUP] ERROR al guardar en OpenSearch:', saveErr && (saveErr.body || saveErr.message || saveErr));
      }
      console.log('[CVE_LOOKUP] Respuesta final enviada al frontend:', JSON.stringify({ analyzer: 'Vulners_CVE_1_0', results: rows, full: fullResult, resumenAI }, null, 2));
      // Responder incluyendo el timestamp para el frontend
      return res.json({ analyzer: 'Vulners_CVE_1_0', results: rows, full: fullResult, resumenAI, timestamp: doc.timestamp });
    } catch (err) {
      console.error('[CVE_LOOKUP] ERROR:', err && (err.response?.data || err.message || err));
      return res.status(500).json({ error: 'Error buscando CVEs para el dominio/IP', detail: err.message });
    }
  }
  // ...existing code for other analyzers...
  if (!cfg) {
    console.error('[ANALYZE] Tipo de análisis no soportado:', analysisType);
    return res.status(400).json({ error: 'Tipo de análisis no soportado' });
  }
  if (cfg.validate && !cfg.validate(target)) {
    console.error('[ANALYZE] Formato incorrecto para este análisis:', target);
    return res.status(400).json({ error: 'Formato incorrecto para este análisis' });
  }
  try {
    const dataType = typeof cfg.type === 'function' ? cfg.type(target) : cfg.type;
    const data     = cfg.build(target);
    const workerId = await resolveWorkerId(cfg.name);
    console.log(`[ANALYZE] workerId: ${workerId}`);
    if (!workerId) throw new Error(`No existe el analizador ${cfg.name} en Cortex`);
    console.log(`[ANALYZE] Enviando job a Cortex: analyzer=${cfg.name}, dataType=${dataType}, data=${data}`);
    const { data: job } = await axios.post(
      `${CORTEX_URL}/api/analyzer/${workerId}/run`,
      { dataType, data },
      { headers: cortexHeaders }
    );
    console.log('[ANALYZE] job object:', JSON.stringify(job, null, 2)); // LOG DEL JOB
    let status = job.status, report = null, tries = 0;
    while (['Waiting', 'InProgress'].includes(status) && tries < 30) {
      await new Promise(r => setTimeout(r, 2000));
      const { data: info } = await axios.get(`${CORTEX_URL}/api/job/${job.id}`, { headers: cortexHeaders });
      status = info.status;
      report = info.report || report;
      tries++;
      console.log(`[ANALYZE] Polling job ${job.id} intento ${tries}: status=${status}`);
      console.log(`[ANALYZE] Respuesta completa del polling (intento ${tries}):`, JSON.stringify(info, null, 2));
    }
    if (status !== 'Success') {
      console.error(`[ANALYZE] El job terminó en estado ${status}`);
      return res.status(502).json({ error: `El job terminó en estado ${status}` });
    }
    if (!report) {
      const { data: rep } = await axios.get(`${CORTEX_URL}/api/job/${job.id}/report`, { headers: cortexHeaders });
      report = rep.report;
    }
    console.log('[ANALYZE] report object:', JSON.stringify(report, null, 2)); // LOG DEL REPORT
    const aiReport = await generateOllamaReport(report, lang || 'es');
    console.log('[ANALYZE] Respuesta Ollama:', aiReport);
    const doc = {
      timestamp: new Date().toISOString(),
      target,
      analyzer: analysisType,
      result: report,
      username: req.user.username, // <-- IMPORTANTE: siempre guardar el username correcto
      role: req.user.role
    };
    await saveReport(doc);
    let rows = [];
    // 1. Extraer filas del análisis normal
    if (cfg.name === 'SmapScan_1_0') {
      let ports = [];
      if (Array.isArray(report.full?.ports)) {
        ports = report.full.ports;
      } else if (Array.isArray(report.ports)) {
        ports = report.ports;
      }
      if (ports.length > 0) {
        rows = ports.map(p => ({
          service: 'Puerto ' + (p.port || p.portid || ''),
          description: p.service || p.state || 'Abierto',
          details: `Protocolo: ${p.protocol || ''}`
        }));
      }
      if (!rows.length && report.full?.output) {
        // Si es salida de Nmap, recortar solo la tabla de puertos
        let output = report.full.output;
        // Buscar la sección de puertos (desde la primera línea que contiene 'PORT' hasta la última línea que contiene '/tcp' o '/udp')
        const portTableMatch = output.match(/PORT[\s\S]+?(\d+\/tcp[\s\S]+?)(Nmap done:|$)/i);
        if (portTableMatch) {
          // Extraer solo la tabla de puertos
          let portLines = portTableMatch[0]
            .replace(/.*PORT.*\n/i, 'PORT STATE SERVICE VERSION\n') // Normalizar encabezado
            .replace(/Nmap done:.*/i, '') // Quitar pie
            .trim();
          rows = [{ service: 'Escaneo de puertos', description: portLines, details: '' }];
        } else {
          // Si no se puede recortar, mostrar el output completo
          rows = [{ service: 'Escaneo de puertos', description: output, details: '' }];
        }
      }
      if (!rows.length) {
        rows = [{ service: 'Escaneo de puertos', description: 'No se encontraron puertos abiertos o no hay datos.', details: '' }];
      }
    } else if (cfg.name === 'Crt_sh_Transparency_Logs_1_0') {
      const certList = report.full?.certobj?.result || report.certobj?.result || [];
      const subs = [...new Set(certList.flatMap(r => (r.name_value || '').split(/\s+/)).filter(Boolean))];
      rows = subs.map(name => ({ service: 'Subdomain', description: name, details: 'Detectado por crt.sh' }));
    } else if (Array.isArray(report.summary?.taxonomies)) {
      rows = report.summary.taxonomies.map(t => ({ service: t.predicate, description: t.namespace, details: t.value }));
    } else if (Array.isArray(report.full?.exploits)) {
      rows = report.full.exploits.map(e => ({ service: 'Exploit', description: e.title, details: e.published ?? '' }));
    } else if (cfg.name === 'Vulners_CVE_1_0' && Array.isArray(report.results)) {
      // Unificar CVE/exploit a la misma estructura que los otros analizadores
      if (report.results.length > 0) {
        rows = report.results.map(cve => ({
          service: cve.service || cve.id || '-',
          description: cve.description || cve.details || cve.title || '-',
          details: [
            cve.details || '',
            cve.cvss && cve.cvss.score ? `CVSS: ${cve.cvss.score}` : '',
            cve.cvss && cve.cvss.vector ? `Vector: ${cve.cvss.vector}` : '',
            cve.references ? `Referencias: ${(Array.isArray(cve.references) ? cve.references.join(', ') : cve.references)}` : '',
            cve.url ? `URL: ${cve.url}` : '',
            cve.published ? `Publicado: ${cve.published}` : '',
            cve.lastseen ? `Última vez visto: ${cve.lastseen}` : ''
          ].filter(Boolean).join(' | ')
        }));
      } else {
        // Si no hay resultados, mostrar el informe AI aunque sea solo texto
        rows = [{ service: '-', description: aiReport || 'Sin resumen disponible', details: '' }];
      }
    }
    // 2. Si no hay filas, intentar extraer entidades del informe AI (Ollama)
    if (!rows.length && aiReport && typeof aiReport === 'string') {
      // Buscar posibles puertos, subdominios o CVEs en el texto de Ollama
      const aiRows = [];
      // Buscar puertos (ej: 80/tcp, 443/tcp)
      const portRegex = /\b(\d{1,5})\/(tcp|udp)\b/gi;
      let match;
      while ((match = portRegex.exec(aiReport)) !== null) {
        aiRows.push({ service: 'Puerto ' + match[1], description: match[2].toUpperCase(), details: 'Detectado por IA' });
      }
      // Buscar subdominios (ej: sub.example.com)
      const subdomainRegex = /\b([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z]{2,})\b/g;
      let subMatch;
      while ((subMatch = subdomainRegex.exec(aiReport)) !== null) {
        aiRows.push({ service: 'Subdomain', description: subMatch[1], details: 'Detectado por IA' });
      }
      // Buscar CVEs (ej: CVE-2023-1234)
      const cveRegex = /\bCVE-\d{4}-\d{4,}\b/gi;
      let cveMatch;
      while ((cveMatch = cveRegex.exec(aiReport)) !== null) {
        aiRows.push({ service: 'CVE', description: cveMatch[0], details: 'Detectado por IA' });
      }
      if (aiRows.length) {
        rows = aiRows;
      }
    }
    // 3. Si sigue sin haber filas, mensaje por defecto
    if (!rows.length) rows = [{ service: '-', description: aiReport || 'Sin resumen disponible', details: 'Revisa el informe completo en Cortex o IA' }];
    // Adjuntar el resumen AI al objeto full para que siempre esté visible en el informe completo
    if (report && typeof report === 'object') {
      report.aiReport = aiReport;
    }
    // Enviar el resumen AI como campo separado y no como parte de 'full' para evitar confusión en el frontend
    console.log('[ANALYZE] Respuesta final enviada al frontend:', JSON.stringify({ analyzer: cfg.name, results: rows, full: report, resumenAI: aiReport }, null, 2));
    return res.json({ analyzer: cfg.name, results: rows, full: report, resumenAI: aiReport });
  } catch (err) {
    console.error('[ANALYZE] ERROR:', err && (err.response?.data || err.message || err));
    const detail = err.response?.data?.message || err.message || 'Error desconocido';
    res.status(500).json({ error: 'Error comunicándose con Cortex', detail });
  }
});

app.get('/api/history', authMiddleware, async (req, res) => {
  await checkIndex();
  try {
    const isAdmin = req.user.role === 'admin';
    const lang = req.query.lang || 'es';
    const query = isAdmin ? { match_all: {} } : { term: { username: req.user.username } };
    let results = await getDecryptedReports(query);
    // Para cada análisis, extraer resumen de resultados (servicio, descripción, detalles)
    const history = results.map(r => {
      // Mostrar SIEMPRE la fila en el historial, aunque no haya resumen
      let resumen = [];
      if (Array.isArray(r.result?.results) && r.result.results.length > 0) {
        resumen = r.result.results.map(x => ({
          service: x.service || x.id || '-',
          description: (x.description && x.description !== '-') ? x.description : (x.title || x.details || x.id || x.service || '-'),
          details: x.details || x.cvss || x.references || ''
        }));
      } else if (r.analyzer === 'cve_lookup' || r.analyzer === 'Vulners_CVE_1_0') {
        // Si no hay results, igual mostrar la fila en historial
        resumen = [{
          service: '-',
          description: 'Análisis de CVEs realizado',
          details: ''
        }];
      }
      return {
        timestamp: r.timestamp,
        target: r.target,
        analyzer: (r.analyzer === 'cve_lookup' || r.analyzer === 'Vulners_CVE_1_0') ? 'CVES' : r.analyzer,
        resumen
      };
    });
    res.json({ history });
  } catch (err) {
    res.status(500).json({ error: 'Error obteniendo historial', detail: err.message });
  }
});

app.get('/api/download-report', authMiddleware, async (req, res) => {
  await checkIndex();
  try {
    const isAdmin = req.user.role === 'admin';
    const lang = req.query.lang || 'es';
    const query = isAdmin ? { match_all: {} } : { term: { username: req.user.username } };
    let docs = await getDecryptedReports(query);
    for (const d of docs) {
      if (!d.aiReport) {
        console.log('[PDF] Generando informe AI para:', d.analyzer, d.target);
        d.aiReport = await generateOllamaReport(d.result, lang);
        console.log('[PDF] Respuesta Ollama:', d.aiReport);
      }
    }
    const doc = new PDFDocument();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="informe.pdf"');
    doc.pipe(res);
    doc.fontSize(18).text('Informe de Análisis de Superficie de Ataque', { align: 'center' });
    doc.moveDown();
    docs = docs.filter(d => d && d.timestamp && d.username && d.analyzer && d.result);
    console.log('Docs recuperados para PDF:', docs);
    if (docs.length === 0) {
      doc.fontSize(14).text('No hay informes disponibles para este usuario.', { align: 'center' });
      doc.end();
      return;
    }
    for (const d of docs) {
      doc.fontSize(12).text(`Fecha: ${d.timestamp}`);
      doc.text(`Usuario: ${d.username} (${d.role})`);
      doc.text(`Target: ${d.target}`);
      doc.text(`Tipo de análisis: ${d.analyzer}`);
      doc.moveDown(0.5);
      doc.font('Helvetica-Bold').text('Reporte técnico completo (Cortex):');
      doc.font('Helvetica').fontSize(9).text(JSON.stringify(d.result, null, 2), {lineGap: 2});
      doc.moveDown();
      if (d.aiReport) {
        doc.font('Helvetica-Bold').fontSize(12).text('Informe AI (Ollama):');
        doc.font('Helvetica').fontSize(10).text(d.aiReport, {lineGap: 2});
        doc.moveDown();
      }
      doc.end();
    }
    return;
  } catch (err) {
    res.status(500).json({ error: 'Error generando PDF', detail: err.message });
  }
});

// Descargar solo un informe por timestamp
app.get('/api/download-report/:timestamp', authMiddleware, async (req, res) => {
  await checkIndex();
  try {
    const isAdmin = req.user.role === 'admin';
    const timestamp = req.params.timestamp;
    if (!timestamp) return res.status(400).json({ error: 'Falta el timestamp.' });
    const query = isAdmin ? { term: { timestamp } } : { bool: { must: [ { term: { username: req.user.username } }, { term: { timestamp } } ] } };
    let docs = await getDecryptedReports(query, 1);
    if (!docs.length) {
      return res.status(404).json({ error: 'No se encontró el informe.' });
    }
    const d = docs[0];
    if (!d.aiReport) {
      d.aiReport = await generateOllamaReport(d.result, req.query.lang || 'es');
    }
    const doc = new PDFDocument();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="informe_${d.analyzer}_${d.target}.pdf"`);
    doc.pipe(res);
    doc.fontSize(18).text('Informe de Análisis de Superficie de Ataque', { align: 'center' });
    doc.moveDown();
    doc.fontSize(12).text(`Fecha: ${d.timestamp}`);
    doc.text(`Usuario: ${d.username} (${d.role})`);
    doc.text(`Target: ${d.target}`);
    doc.text(`Tipo de análisis: ${d.analyzer}`);
    doc.moveDown(0.5);
    doc.font('Helvetica-Bold').text('Reporte técnico completo (Cortex):');
    doc.font('Helvetica').fontSize(9).text(JSON.stringify(d.result, null, 2), {lineGap: 2});
    doc.moveDown();
    if (d.aiReport) {
      doc.font('Helvetica-Bold').fontSize(12).text('Informe AI (Ollama):');
      doc.font('Helvetica').fontSize(10).text(d.aiReport, {lineGap: 2});
      doc.moveDown();
    }
    doc.end();
  } catch (err) {
    res.status(500).json({ error: 'Error generando PDF', detail: err.message });
  }
});

// Endpoint para que el admin borre el historial de un usuario específico
app.delete('/api/history/:username', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Solo el administrador puede borrar historiales de otros usuarios.' });
  }
  const username = req.params.username;
  if (!username) {
    return res.status(400).json({ error: 'Falta el nombre de usuario.' });
  }
  try {
    await checkIndex();
    const result = await searchClient.deleteByQuery({
      index: INDEX_NAME,
      body: { query: { term: { username } } },
      refresh: true
    });
    res.json({ success: true, deleted: result.body.deleted || 0 });
  } catch (err) {
    res.status(500).json({ error: 'Error borrando historial', detail: err.message });
  }
});

// --- SESSION & PASSPORT CONFIG ---
app.use(session({
  secret: process.env.SESSION_SECRET || 'sessionsecret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true if using HTTPS
}));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.username);
});
passport.deserializeUser((username, done) => {
  const users = readUsers();
  const user = users.find(u => u.username === username);
  done(null, user || false);
});

// --- GOOGLE OAUTH STRATEGY ---
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:8080/auth/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
  // Use email as username
  const email = profile.emails && profile.emails[0] && profile.emails[0].value;
  if (!email) return done(null, false);
  let users = readUsers();
  let user = users.find(u => u.username === email);
  if (!user) {
    user = { username: email, password: '', role: 'user', googleId: profile.id };
    users.push(user);
    writeUsers(users);
    await saveUserToDB(user); // <-- Añadido: guardar usuario Google en OpenSearch
  } else {
    // Update googleId if not present
    if (!user.googleId) {
      user.googleId = profile.id;
      writeUsers(users);
      await saveUserToDB(user); // <-- Añadido: actualizar usuario Google en OpenSearch
    }
  }
  return done(null, user);
}));

// --- GOOGLE OAUTH ROUTES ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/?login=failed', session: false }), (req, res) => {
  // Successful authentication, issue JWT and redirect with token
  const user = req.user;
  const token = generateToken(user);
  // Redirect to frontend with token as query param (adjust as needed)
  res.redirect(`/auth-success.html?token=${token}&role=${user.role}`);
});

// MIGRACIÓN: Guardar todos los usuarios de users.json en OpenSearch al iniciar el servidor
async function migrateUsersToOpenSearch() {
  const users = readUsers();
  for (const user of users) {
    await saveUserToDB(user);
  }
  console.log('Migración de users.json a OpenSearch completada.');
}

// Llama a checkUserIndex, checkIndex y migración al iniciar el servidor
(async () => {
  try {
    await checkUserIndex();
    await checkIndex();
    await migrateUsersToOpenSearch(); // <-- migrar usuarios locales
    // await searchClient.deleteByQuery({
    //   index: INDEX_NAME,
    //   body: { query: { match_all: {} } },
    //   refresh: true
    // });
    // console.log('Todos los documentos del índice analisis han sido eliminados al iniciar el servidor.');
  } catch (err) {
    console.warn('No se pudo limpiar el índice analisis al iniciar:', err && (err.body || err.message || err));
  }
})();

/*  start server */
app.listen(PORT, () => console.log(`Web escuchando en http://localhost:${PORT}`));

// Reanalizar un análisis anterior y actualizar el documento existente
app.post('/api/reanalyze', authMiddleware, async (req, res) => {
  await checkIndex();
  const { timestamp } = req.body;
  if (!timestamp) {
    return res.status(400).json({ error: 'Falta el timestamp del análisis a reanalizar.' });
  }
  try {
    // Buscar el análisis anterior por timestamp y usuario (obteniendo el _id de OpenSearch)
    const searchRes = await searchClient.search({
      index: INDEX_NAME,
      size: 1,
      body: {
        query: {
          bool: {
            must: [
              { term: { username: req.user.username } },
              { term: { timestamp } }
            ]
          }
        }
      }
    });
    const hit = searchRes.body.hits?.hits?.[0];
    if (!hit) {
      return res.status(404).json({ error: 'No se encontró el análisis anterior.' });
    }
    const prev = JSON.parse(decrypt(hit._source.data));
    const docId = hit._id;
    // Reutilizar la lógica de /api/analyze
    const analysisType = prev.analyzer;
    const target = prev.target;
    const lang = req.body.lang || 'es';
    const cfg = cfgMap[analysisType];
    if (!cfg) {
      return res.status(400).json({ error: 'Tipo de análisis no soportado.' });
    }
    const dataType = typeof cfg.type === 'function' ? cfg.type(target) : cfg.type;
    const data = cfg.build(target);
    const workerId = await resolveWorkerId(cfg.name);
    console.log(`[REANALYZE] workerId: ${workerId}`);
    if (!workerId) throw new Error(`No existe el analizador ${cfg.name} en Cortex`);
    console.log(`[REANALYZE] Enviando job a Cortex: analyzer=${cfg.name}, dataType=${dataType}, data=${data}`);
    const { data: job } = await axios.post(
      `${CORTEX_URL}/api/analyzer/${workerId}/run`,
      { dataType, data },
      { headers: cortexHeaders }
    );
    let status = job.status, report = null, tries = 0;
    while (['Waiting', 'InProgress'].includes(status) && tries < 30) {
      await new Promise(r => setTimeout(r, 2000));
      const { data: info } = await axios.get(`${CORTEX_URL}/api/job/${job.id}`, { headers: cortexHeaders });
      status = info.status;
      report = info.report || report;
      tries++;
      console.log(`[REANALYZE] Polling job ${job.id} intento ${tries}: status=${status}`);
      console.log(`[REANALYZE] Respuesta completa del polling (intento ${tries}):`, JSON.stringify(info, null, 2));
    }
    if (status !== 'Success') {
      return res.status(502).json({ error: `El job terminó en estado ${status}` });
    }
    if (!report) {
      const { data: rep } = await axios.get(`${CORTEX_URL}/api/job/${job.id}/report`, { headers: cortexHeaders });
      report = rep.report;
    }
    const aiReport = await generateOllamaReport(report, lang);
    // Actualizar el documento existente en OpenSearch (manteniendo el mismo timestamp)
    const updatedDoc = {
      username: req.user.username,
      analyzer: analysisType,
      timestamp: prev.timestamp, // mantener el timestamp original
      role: req.user.role,
      target,
      data: encrypt(JSON.stringify({
        timestamp: prev.timestamp,
        target,
        analyzer: analysisType,
        result: report,
        username: req.user.username,
        role: req.user.role
      }))
    };
    await searchClient.update({
      index: INDEX_NAME,
      id: docId,
      body: { doc: updatedDoc },
      refresh: 'true'
    });
    res.json({ analyzer: cfg.name, result: report, resumenAI: aiReport });
  } catch (err) {
    res.status(500).json({ error: 'Error reanalizando', detail: err.message });
  }
});