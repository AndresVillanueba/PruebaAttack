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
// Servir archivos estáticos de toda la raíz del proyecto (incluyendo attack-stix-data)
app.use(express.static(path.join(__dirname, '..')));

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
  // Validación: mínimo 3 caracteres, sin espacios
  if (!username || !password || username.length < 3 || password.length < 3 || /\s/.test(username) || /\s/.test(password)) {
    return res.status(400).json({ error: 'Usuario y contraseña deben tener al menos 3 caracteres y no contener espacios.' });
  }
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

// Login de usuario
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  // Validación: mínimo 3 caracteres, sin espacios
  if (!username || !password || username.length < 3 || password.length < 3 || /\s/.test(username) || /\s/.test(password)) {
    return res.status(400).json({ error: 'Usuario y contraseña deben tener al menos 3 caracteres y no contener espacios.' });
  }
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

// --- PASSPORT GOOGLE OAUTH2 ---
app.use(session({
  secret: process.env.SESSION_SECRET || 'pon-un-secreto-aleatorio-aqui',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.username);
});
passport.deserializeUser((username, done) => {
  let user = readUsers().find(u => u.username === username);
  done(null, user);
});

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
  let users = readUsers();
  let user = users.find(u => u.googleId === profile.id || u.username === profile.emails[0].value);
  if (!user) {
    user = {
      username: profile.emails[0].value,
      password: '',
      role: 'user',
      googleId: profile.id
    };
    users.push(user);
    writeUsers(users);
  } else {
    // Actualiza googleId si no está
    if (!user.googleId) {
      user.googleId = profile.id;
      writeUsers(users);
    }
  }
  return done(null, user);
}));

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  // Genera un JWT para el usuario Google
  const token = generateToken(req.user);
  // Redirige al frontend con el token y rol como parámetros
  res.redirect(`/auth-success.html?token=${token}&role=${req.user.role}`);
});

// Lanzar análisis
app.post('/api/analyze', authMiddleware, async (req, res) => {
  await checkIndex();
  const { target, analysisType, lang } = req.body;
  // Validación de IP o dominio
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const domainRegex = /^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$/;
  if (!ipRegex.test(target) && !domainRegex.test(target)) {
    return res.status(400).json({ error: 'Introduce una IP válida (ej: 192.168.1.1) o un dominio válido (ej: ejemplo.com)' });
  }
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
        // Si es salida de Smap, recortar solo la tabla de puertos
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
    console.log('[ANALYZE] Respuesta final enviada al frontend:', JSON.stringify({ analyzer: cfg.name, results: rows, full: report, resumenAI: aiReport, timestamp: doc.timestamp }, null, 2));
    return res.json({ analyzer: cfg.name, results: rows, full: report, resumenAI: aiReport, timestamp: doc.timestamp });
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
    const from = req.query.from;
    const to = req.query.to;
    let query = isAdmin ? { match_all: {} } : { term: { username: req.user.username } };
    // Si hay filtro de fechas, añadirlo al query
    if (from || to) {
      const range = {};
      if (from) range.gte = from;
      if (to) range.lte = to;
      query = {
        bool: {
          must: [isAdmin ? { match_all: {} } : { term: { username: req.user.username } }],
          filter: [{ range: { timestamp: range } }]
        }
      };
    }
    let results = await getDecryptedReports(query);
    // Para cada análisis, extraer resumen de resultados (servicio, descripción, detalles)
    const history = await Promise.all(results.map(async r => {
      let resumen = [];
      // Quitar correlación MITRE del historial
      if (r.result && Array.isArray(r.result.results)) {
        resumen = r.result.results.map(x => ({ service: x.service, description: x.description }));
      }
      return { ...r, resumen };
    }));
    res.json({ history });
  } catch (err) {
    res.status(500).json({ error: 'Error obteniendo historial', detail: err.message });
  }
});

// --- Descargar informe PDF por timestamp ---
app.get('/api/download-report/:timestamp', authMiddleware, async (req, res) => {
  await checkIndex();
  const timestamp = req.params.timestamp;
  try {
    // Buscar el análisis por timestamp exacto
    const { body } = await searchClient.search({
      index: INDEX_NAME,
      body: { query: { term: { timestamp } } },
      size: 1
    });
    if (!body.hits.hits.length) return res.status(404).json({ error: 'Análisis no encontrado' });
    // Desencriptar y parsear
    const doc = body.hits.hits[0]._source;
    const data = JSON.parse(decrypt(doc.data));
    // Generar PDF simple
    const pdf = new PDFDocument();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="informe.pdf"');
    pdf.pipe(res);
    pdf.fontSize(18).text('Informe de Análisis', { align: 'center' });
    pdf.moveDown();
    pdf.fontSize(12).text('Timestamp: ' + (data.timestamp || '-'));
    pdf.text('Target: ' + (data.target || '-'));
    pdf.text('Tipo: ' + (data.analyzer || '-'));
    pdf.text('Usuario: ' + (data.username || '-'));
    pdf.text('Rol: ' + (data.role || '-'));
    pdf.moveDown();
    pdf.fontSize(14).text('Resultados:', { underline: true });
    if (data.result && Array.isArray(data.result.results)) {
      data.result.results.forEach((r, i) => {
        pdf.moveDown(0.5);
        pdf.fontSize(12).text(`${i + 1}. Servicio: ${r.service || '-'}\n   Descripción: ${r.description || '-'}\n   Detalles: ${r.details || '-'}`);
      });
    } else {
      pdf.fontSize(12).text('No hay resultados técnicos.');
    }
    pdf.end();
  } catch (err) {
    res.status(500).json({ error: 'Error generando PDF', detail: err.message });
  }
});

// --- Rutas de prueba para desarrollo ---
app.get('/api/test/ollama', async (req, res) => {
  const url = `http://localhost:${OLLAMA_PORT}/api/generate`;
  const prompt = 'Eres un experto en ciberseguridad. Resume los siguientes hallazgos: ' + JSON.stringify(req.query.data);
  const payload = { model: OLLAMA_MODEL, prompt, stream: false };
  try {
    const response = await axios({ method: 'post', url, data: payload, responseType: 'json' });
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ error: 'Error llamando a Ollama', detail: err.message });
  }
});

app.get('/api/test/vulners', async (req, res) => {
  if (!process.env.VULNERS_API_KEY) return res.status(500).json({ error: 'API Key de Vulners no configurada' });
  try {
    const response = await axios.get('https://vulners.com/api/v3/search/lucene/', {
      params: { query: req.query.q, size: 10 },
      headers: { 'Api-Key': process.env.VULNERS_API_KEY }
    });
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ error: 'Error consultando Vulners', detail: err.message });
  }
});

app.get('/api/test/cortex', async (req, res) => {
  const { data } = await axios.get(`${CORTEX_URL}/api/analyzer`, { headers: cortexHeaders });
  res.json(data);
});

// --- Página de agradecimiento ---
app.get('/api/gracias', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>¡Gracias por usar nuestro servicio!</title>
        <style>
          body { font-family: Arial, sans-serif; background-color: #f4f4f9; margin: 0; padding: 0; }
          .container { max-width: 800px; margin: 50px auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); }
          h1 { text-align: center; color: #333; }
          p { line-height: 1.6; color: #555; }
          .footer { text-align: center; margin-top: 20px; font-size: 0.9em; color: #777; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>¡Gracias por usar nuestro servicio de análisis de seguridad!</h1>
          <p>Su informe ha sido generado exitosamente. Puede descargarlo desde la sección de historial.</p>
          <p>Si tiene alguna pregunta o necesita asistencia adicional, no dude en contactarnos.</p>
          <div class="footer">
            <p>Correo electrónico: soporte@seguridad.com</p>
            <p>Teléfono: +34 912 345 678</p>
          </div>
        </div>
      </body>
    </html>
  `);
});

// --- Página de error 404 ---
app.use((req, res) => {
  res.status(404).send(`
    <html>
      <head>
        <title>Página no encontrada</title>
        <style>
          body { font-family: Arial, sans-serif; background-color: #f4f4f9; margin: 0; padding: 0; }
          .container { max-width: 600px; margin: 100px auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); }
          h1 { text-align: center; color: #333; }
          p { line-height: 1.6; color: #555; }
          a { color: #007bff; text-decoration: none; }
          a:hover { text-decoration: underline; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Página no encontrada</h1>
          <p>Lo sentimos, la página que estás buscando no existe.</p>
          <p>Volver a <a href="/">Inicio</a></p>
        </div>
      </body>
    </html>
  `);
});

// --- Correlación MITRE: función básica para historial ---
async function correlateServiceWithMitre(service) {
  // Aquí deberías implementar la lógica real de correlación con MITRE
  // Por ahora, devuelve un array vacío o un ejemplo si el servicio contiene palabras clave
  // Puedes mejorar esto usando tus datos MITRE locales
  const mitreExamples = {
    'ssh': [{ id: 'T1021.004', name: 'Remote Services: SSH', url: 'https://attack.mitre.org/techniques/T1021/004/' }],
    'rdp': [{ id: 'T1021.001', name: 'Remote Services: RDP', url: 'https://attack.mitre.org/techniques/T1021/001/' }],
    'http': [{ id: 'T1190', name: 'Exploit Public-Facing Application', url: 'https://attack.mitre.org/techniques/T1190/' }]
  };
  const key = Object.keys(mitreExamples).find(k => service.toLowerCase().includes(k));
  return key ? mitreExamples[key] : [];
}

// --- ADMIN: Insertar análisis manualmente ---
app.post('/api/admin/analysis', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Solo el admin puede insertar análisis' });
  await checkIndex();
  const doc = req.body;
  try {
    await saveReport(doc);
    res.json({ ok: true, message: 'Análisis insertado correctamente' });
  } catch (err) {
    res.status(500).json({ error: 'Error insertando análisis', detail: err.message });
  }
});

// --- ADMIN: Borrar análisis por timestamp ---
app.delete('/api/admin/analysis/:timestamp', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Solo el admin puede borrar análisis' });
  await checkIndex();
  const timestamp = req.params.timestamp;
  try {
    // Buscar todos los documentos por timestamp (sin filtrar por usuario)
    const { body } = await searchClient.search({
      index: INDEX_NAME,
      body: { query: { term: { timestamp } } },
      size: 100 // por si hay muchos duplicados
    });
    if (!body.hits.hits.length) return res.status(404).json({ error: 'Análisis no encontrado' });
    // Borrar todos los documentos con ese timestamp
    for (const hit of body.hits.hits) {
      await searchClient.delete({ index: INDEX_NAME, id: hit._id });
    }
    res.json({ ok: true, message: 'Análisis borrado correctamente' });
  } catch (err) {
    res.status(500).json({ error: 'Error borrando análisis', detail: err.body?.error?.reason || err.message });
  }
});

// --- ADMIN: Actualizar análisis por timestamp ---
app.put('/api/admin/analysis/:timestamp', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Solo el admin puede actualizar análisis' });
  await checkIndex();
  const timestamp = req.params.timestamp;
  const updateDoc = req.body;
  try {
    // Buscar todos los documentos por timestamp
    const { body } = await searchClient.search({
      index: INDEX_NAME,
      body: { query: { term: { timestamp } } },
      size: 100
    });
    if (!body.hits.hits.length) return res.status(404).json({ error: 'Análisis no encontrado' });
    // Actualizar todos los documentos con ese timestamp
    for (const hit of body.hits.hits) {
      await searchClient.update({
        index: INDEX_NAME,
        id: hit._id,
        body: { doc: updateDoc }
      });
    }
    res.json({ ok: true, message: 'Análisis actualizado correctamente' });
  } catch (err) {
    res.status(500).json({ error: 'Error actualizando análisis', detail: err.body?.error?.reason || err.message });
  }
});

// --- Ruta temporal para insertar análisis de prueba ---
app.post('/api/admin/insert-demo-analysis', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Solo el admin puede insertar análisis demo' });
  await checkIndex();
  const now = new Date().toISOString();
  const doc = {
    timestamp: now,
    target: req.body.target || 'demo.com',
    analyzer: req.body.analyzer || 'attack_surface_scan',
    username: req.user.username,
    role: req.user.role,
    result: req.body.result || { results: [{ service: 'Puerto 80/tcp', description: 'HTTP abierto', details: 'Demo' }] }
  };
  try {
    await saveReport(doc);
    res.json({ ok: true, message: 'Demo análisis insertado', timestamp: now });
  } catch (err) {
    res.status(500).json({ error: 'Error insertando demo', detail: err.message });
  }
});

// --- Servir archivos estáticos SOLO después de las rutas de API ---
app.use(express.static(path.join(__dirname, '..')));

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
  checkIndex();
  checkUserIndex();
});