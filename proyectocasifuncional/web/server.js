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
const nodemailer = require('nodemailer');
// Usar una alternativa para generar tokens aleatorios
// const cryptoRandomString = require('crypto-random-string');

const app        = express();
const PORT       = process.env.PORT || 8080;
const CORTEX_URL = process.env.CORTEX_URL || 'http://localhost:9001';
const API_KEY    = process.env.CORTEX_API_KEY;
const OPENSEARCH_HOST = 'http://localhost:9200';
const INDEX_NAME = 'analisis';

/* Configuración Ollama  */
const OLLAMA_PORT  = process.env.OLLAMA_PORT  || 11434;   // puerto por defecto: 11434
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'llama3'; 

/* Configuración para envío de correos */
const EMAIL_USER = process.env.EMAIL_USER || 'test@example.com';
const EMAIL_PASS = process.env.EMAIL_PASS || 'password123';
const EMAIL_HOST = process.env.EMAIL_HOST || 'smtp.gmail.com';
const EMAIL_PORT = process.env.EMAIL_PORT || 587;
const EMAIL_FROM = process.env.EMAIL_FROM || `"ATTACK-SENTINEL" <${EMAIL_USER}>`;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

/* Configuración del transportador de correo */
const transporter = nodemailer.createTransport({
  host: EMAIL_HOST,
  port: EMAIL_PORT,
  secure: EMAIL_PORT === 465,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false // Útil en desarrollo, eliminar en producción
  }
});

/* Verificar la configuración de correo al iniciar */
transporter.verify()
  .then(() => console.log('Servidor de correo configurado correctamente'))
  .catch(error => console.error('Error en la configuración del servidor de correo:', error));

/* Cliente OpenSearch */
const searchClient = new Client({ node: OPENSEARCH_HOST });

// Función para verificar la conectividad con OpenSearch
async function checkOpenSearchConnection() {
  try {
    console.log(`Verificando conexión a OpenSearch en ${OPENSEARCH_HOST}...`);
    const { body: info } = await searchClient.info();
    
    console.log('Conexión a OpenSearch exitosa');
    console.log(`Versión: ${info.version.number}`);
    console.log(`Nombre del clúster: ${info.cluster_name}`);
    
    return true;
  } catch (error) {
    console.error('Error de conexión a OpenSearch:', error.message);
    console.log('ADVERTENCIA: La aplicación funcionará con almacenamiento local de respaldo.');
    return false;
  }
}

// Verificar conexión al inicio
checkOpenSearchConnection()
  .then(connected => {
    if (connected) {
      // Verificar índices si hay conexión
      checkIndex();
      checkUserIndex();
    }
  })
  .catch(err => {
    console.error('Error verificando conexión a OpenSearch:', err);
  });

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
    // Verificar si el índice existe
    const { body: exists } = await searchClient.indices.exists({ index: 'usuarios' });
    
    if (!exists) {
      console.log('No se ha encontrado el índice de usuarios, creando...');
      
      // Crear el índice con mappings apropiados
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
              googleId: { type: 'keyword' },
              resetToken: { type: 'keyword' },
              resetTokenExpires: { type: 'date' },
              passwordLastChanged: { type: 'date' },
              email: { type: 'keyword' },
              createdAt: { type: 'date' },
              updatedAt: { type: 'date' }
            }
          }
        }
      });
      
      console.log('Índice de usuarios creado correctamente');
    } else {
      // El índice existe, verificar mappings (opcional)
      try {
        const { body: mapping } = await searchClient.indices.getMapping({
          index: 'usuarios'
        });
        
        // Verificar que el mapping tenga los campos clave
        const properties = mapping.usuarios.mappings.properties;
        const requiredFields = ['username', 'password', 'role', 'createdAt', 'updatedAt'];
        
        const missingFields = requiredFields.filter(field => !properties[field]);
        if (missingFields.length > 0) {
          console.warn(`Advertencia: Faltan campos en el mapping: ${missingFields.join(', ')}`);
        }
      } catch (mappingError) {
        console.error('Error al verificar mappings:', mappingError.message);
      }
    }
    
    return true;
  } catch (error) {
    console.error('Error comprobando/creando índice de usuarios:', error.message);
    if (error.meta && error.meta.body) {
      console.error('Detalles del error:', JSON.stringify(error.meta.body, null, 2));
    }
    return false;
  }
}

if (!API_KEY) console.warn('CORTEX_API_KEY no está definido; la web no podrá llamar a Cortex');

// Middleware para desactivar caché completamente
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

// Middleware para desactivar caché en archivos HTML y asegurar que admin-panel.html nunca se cachee
app.use((req, res, next) => {
  if (req.path.endsWith('.html')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
});

app.use(express.static(path.join(__dirname), {
  setHeaders: (res, path) => {
    if (path.endsWith('.html') || path.endsWith('.js') || path.endsWith('.css')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
}));
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
  const maxRetries = 3;
  let attempt = 0;
  
  while (attempt < maxRetries) {
    try {
      await checkUserIndex(); // Asegurar que el índice exista
      
      if (!user || !user.username) {
        console.error('Error: Intento de guardar usuario sin nombre de usuario');
        return false;
      }
      
      // Normalizar y validar los campos del usuario
      const username = user.username.toLowerCase();
      
      // Extraer todos los campos relevantes del usuario
      const userToSave = {
        username: username,
        password: user.password, // hashed o vacío para Google
        role: user.role || 'user',
        googleId: user.googleId || null,
        resetToken: user.resetToken || null,
        resetTokenExpires: user.resetTokenExpires || null,
        passwordLastChanged: user.passwordLastChanged || null,
        email: user.email || null,
        createdAt: user.createdAt || Date.now(),
        updatedAt: Date.now()
      };
      
      console.log('Guardando usuario en DB:', JSON.stringify({...userToSave, password: '***REDACTED***'}, null, 2));
      
      // Verificar si el usuario ya existe
      const exists = await searchClient.exists({
        index: 'usuarios',
        id: username
      }).catch(err => {
        console.warn('Error verificando existencia del usuario:', err.message);
        return { body: false }; // Si hay error, asumimos que no existe
      });
      
      // Usar el username como _id para evitar duplicados y permitir upsert
      const response = await searchClient.update({
        index: 'usuarios',
        id: username,
        body: {
          doc: userToSave,
          doc_as_upsert: true
        },
        refresh: 'true'
      });

      console.log(`Usuario ${username} ${exists.body ? 'actualizado' : 'creado'} correctamente en OpenSearch`);
      return true;
      
    } catch (error) {
      attempt++;
      console.error(`Error al guardar usuario en DB (intento ${attempt}/${maxRetries}):`, error.message);
      if (error.meta && error.meta.body) {
        console.error('Detalles del error:', JSON.stringify(error.meta.body, null, 2));
      }
      
      if (attempt < maxRetries) {
        const delay = Math.pow(2, attempt) * 1000; // Exponential backoff
        console.log(`Reintentando en ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  console.error('Se agotaron los intentos de guardar el usuario en DB');
  return false;
}

async function getUserFromDB(username) {
  try {
    await checkUserIndex(); // Asegurar que el índice exista
    
    if (!username) {
      console.error('Error: Intento de recuperar usuario sin proporcionar nombre de usuario');
      return null;
    }
    
    // Normalizar username
    const normalizedUsername = username.toLowerCase();
    
    // Intentar obtener por ID primero (más eficiente)
    try {
      const { body } = await searchClient.get({
        index: 'usuarios',
        id: normalizedUsername
      });
      
      if (body && body._source) {
        console.log(`Usuario recuperado de DB por ID: ${normalizedUsername}`);
        return body._source;
      }
    } catch (idError) {
      // Si no se encuentra por ID, continuamos con la búsqueda por término
      console.log(`Usuario no encontrado por ID: ${normalizedUsername}, intentando búsqueda por término`);
    }
    
    // Búsqueda alternativa por término
    const { body } = await searchClient.search({
      index: 'usuarios',
      body: { 
        query: { 
          term: { 
            username: normalizedUsername 
          } 
        } 
      },
      size: 1
    });
    
    if (body.hits.hits.length > 0) {
      const user = body.hits.hits[0]._source;
      console.log(`Usuario recuperado de DB por búsqueda: ${normalizedUsername}`);
      return user;
    }
    
    console.log(`Usuario no encontrado en DB: ${normalizedUsername}`);
    return null;
  } catch (error) {
    console.error(`Error al recuperar usuario de DB (${username}):`, error.message);
    if (error.meta && error.meta.body) {
      console.error('Detalles del error:', JSON.stringify(error.meta.body, null, 2));
    }
    return null;
  }
}

// Función para obtener un usuario directamente por ID de OpenSearch
async function getUserByIdFromDB(id) {
  try {
    // Verificar que el ID no está vacío
    if (!id) {
      console.error('Error: Se intentó obtener un usuario con ID vacío');
      return null;
    }
    
    await checkUserIndex(); // Asegurar que el índice existe
    
    try {
      const { body } = await searchClient.get({
        index: 'usuarios',
        id: id.toLowerCase()
      });
      
      if (body && body._source) {
        console.log(`Usuario recuperado de DB por ID: ${id}`);
        return {
          ...body._source,
          id: body._id
        };
      }
    } catch (error) {
      // Si el documento no existe, el error es normal
      if (error.meta && error.meta.statusCode === 404) {
        console.log(`Usuario con ID ${id} no encontrado en OpenSearch`);
        return null;
      }
      
      // Para otros errores, lanzar excepción
      console.error(`Error al recuperar usuario por ID ${id}:`, error.message);
      throw error;
    }
    
    return null;
  } catch (error) {
    console.error(`Error al buscar usuario por ID (${id}):`, error.message);
    return null;
  }
}

// Función para obtener todos los usuarios desde OpenSearch
async function getAllUsersFromDB(size = 100) {
  try {
    await checkUserIndex(); // Asegurar que el índice exista
    
    // Verificar si hay usuarios en el índice
    const { body: indexStats } = await searchClient.count({
      index: 'usuarios'
    });
    
    if (indexStats.count === 0) {
      console.log('No hay usuarios en OpenSearch, verificando la necesidad de migración');
      // Revisar si hay usuarios en el archivo que necesiten ser migrados
      const fileUsers = readUsers();
      if (fileUsers.length > 0) {
        console.log(`Encontrados ${fileUsers.length} usuarios en el archivo, se recomienda migrar`);
      }
      return [];
    }
    
    const { body } = await searchClient.search({
      index: 'usuarios',
      size: size,
      body: {
        query: { match_all: {} },
        sort: [{ updatedAt: { order: 'desc' } }]
      }
    });
    
    if (body.hits && body.hits.hits) {
      const users = body.hits.hits.map(hit => ({
        ...hit._source,
        id: hit._id
      }));
      
      console.log(`Recuperados ${users.length} usuarios de OpenSearch`);
      return users;
    }
    
    return [];
  } catch (error) {
    console.error('Error al recuperar usuarios de OpenSearch:', error.message);
    if (error.meta && error.meta.body) {
      console.error('Detalles del error:', JSON.stringify(error.meta.body, null, 2));
    }
    return [];
  }
}

// Función para eliminar un usuario de OpenSearch
async function deleteUserFromDB(username) {
  try {
    if (!username) {
      console.error('Error: Intento de eliminar usuario sin proporcionar nombre de usuario');
      return false;
    }
    
    const normalizedUsername = username.toLowerCase();
    console.log(`Eliminando usuario ${normalizedUsername} de OpenSearch...`);
    
    // Verificar si el usuario existe antes de intentar eliminarlo
    const userExists = await getUserFromDB(normalizedUsername);
    if (!userExists) {
      console.log(`Usuario ${normalizedUsername} no encontrado en OpenSearch, no hay nada que eliminar`);
      return false;
    }
    
    // Eliminar el usuario usando el ID normalizado
    const { body } = await searchClient.delete({
      index: 'usuarios',
      id: normalizedUsername,
      refresh: 'true'
    });
    
    if (body.result === 'deleted') {
      console.log(`Usuario ${normalizedUsername} eliminado correctamente de OpenSearch`);
      return true;
    } else {
      console.log(`Resultado inesperado al eliminar usuario ${normalizedUsername}:`, body.result);
      return false;
    }
  } catch (error) {
    console.error(`Error al eliminar usuario ${username} de OpenSearch:`, error.message);
    if (error.meta && error.meta.body) {
      console.error('Detalles del error:', JSON.stringify(error.meta.body, null, 2));
    }
    return false;
  }
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
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    console.log('Archivo users.json actualizado correctamente');
    return true;
  } catch (error) {
    console.error('Error al escribir users.json:', error);
    return false;
  }
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

// --- FUNCIONES Y RUTAS ESENCIALES ---

// Registro de usuario
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body;
  
  // Validación: mínimo 3 caracteres, sin espacios
  if (!username || !password || username.length < 3 || password.length < 3 || /\s/.test(username) || /\s/.test(password)) {
    return res.status(400).json({ error: 'Usuario y contraseña deben tener al menos 3 caracteres y no contener espacios.' });
  }
  
  // Normalizar username a minúsculas
  const normalizedUsername = username.toLowerCase();
  
  if (normalizedUsername === 'admin') {
    return res.status(400).json({ success: false, error: 'No puedes registrar el usuario admin.' });
  }
  
  try {
    // Verificar si el usuario ya existe en el archivo local
    const users = readUsers();
    if (users.find(u => u.username.toLowerCase() === normalizedUsername)) {
      return res.status(400).json({ success: false, error: 'Usuario ya existe en el sistema local' });
    }
    
    // Verificar si el usuario ya existe en OpenSearch
    const existingUser = await getUserFromDB(normalizedUsername);
    if (existingUser) {
      return res.status(400).json({ success: false, error: 'Usuario ya existe en la base de datos' });
    }
    
    // Crear el objeto de usuario con timestamp de creación
    const hashed = await bcrypt.hash(password, 10);
    const timestamp = Date.now();
    const userObj = { 
      username: normalizedUsername, 
      password: hashed, 
      role: 'user',
      email: email || null,
      createdAt: timestamp,
      updatedAt: timestamp,
      passwordLastChanged: timestamp
    };
    
    console.log(`Registrando nuevo usuario: ${normalizedUsername}`);
    
    // Primero intentar guardar en OpenSearch (base de datos principal)
    const dbSaveSuccess = await saveUserToDB(userObj);
    if (!dbSaveSuccess) {
      console.error(`Error al guardar usuario ${normalizedUsername} en OpenSearch`);
      return res.status(500).json({ error: 'Error al guardar usuario en la base de datos' });
    }
    
    // Después guardar en el archivo local como respaldo
    users.push(userObj);
    const fileWriteSuccess = writeUsers(users);
    
    if (fileWriteSuccess && dbSaveSuccess) {
      console.log(`Usuario ${normalizedUsername} registrado exitosamente y guardado en ambos almacenamientos`);
      return res.json({ success: true });
    } else {
      console.error(`Error al registrar usuario ${normalizedUsername}: `, 
                   `Archivo: ${fileWriteSuccess ? 'OK' : 'Error'}, `,
                   `DB: ${dbSaveSuccess ? 'OK' : 'Error'}`);
      
      // Si falló el guardado en el archivo pero se guardó en DB, igual es exitoso
      if (dbSaveSuccess) {
        return res.json({ 
          success: true,
          warning: 'Usuario registrado en la base de datos, pero no en el archivo local' 
        });
      }
      
      return res.status(500).json({ 
        error: 'Error al guardar usuario', 
        fileStorage: fileWriteSuccess, 
        dbStorage: dbSaveSuccess 
      });
    }
  } catch (err) {
    console.error('Error en registro de usuario:', err);
    return res.status(500).json({ error: 'Error en el proceso de registro', detail: err.message });
  }
});

// Login de usuario
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  console.log(`Intento de inicio de sesión para: ${username}`);
  
  // Validación: mínimo 3 caracteres, sin espacios
  if (!username || !password || username.length < 3 || password.length < 3 || /\s/.test(username) || /\s/.test(password)) {
    return res.status(400).json({ error: 'Usuario y contraseña deben tener al menos 3 caracteres y no contener espacios.' });
  }
  
  // Primero buscar en users.json que es más confiable
  const users = readUsers();
  let user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
  let userSource = 'json';
  
  // Buscar en la base de datos OpenSearch
  const dbUser = await getUserFromDB(username.toLowerCase());
  
  // Si el usuario existe en el archivo pero no en la base de datos, sincronizamos
  if (user && !dbUser) {
    console.log(`Usuario ${username} encontrado en archivo pero no en DB, sincronizando...`);
    try {
      // Añadir timestamp si no existe
      if (!user.createdAt) user.createdAt = Date.now();
      if (!user.updatedAt) user.updatedAt = Date.now();
      
      await saveUserToDB(user);
      console.log(`Usuario ${username} sincronizado con OpenSearch`);
    } catch (err) {
      console.error(`Error al sincronizar usuario ${username} con OpenSearch:`, err);
    }
  }
  // Si existe en la base de datos pero no en el archivo, actualizamos el archivo
  else if (!user && dbUser) {
    console.log(`Usuario ${username} encontrado en DB pero no en archivo, sincronizando...`);
    user = dbUser;
    userSource = 'db';
    
    // Actualizar el archivo de usuarios
    users.push(user);
    writeUsers(users);
    console.log(`Usuario ${username} añadido al archivo users.json`);
  }
  
  if (!user) {
    console.log(`Usuario no encontrado: ${username}`);
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  }
  
  console.log(`Usuario encontrado en: ${userSource}`);
  console.log(`Datos del usuario: ${JSON.stringify({...user, password: '***REDACTED***'}, null, 2)}`);
  
  // Verificar si la contraseña está hasheada
  const isPasswordHashed = user.password && user.password.startsWith('$2');
  console.log(`¿Contraseña hasheada?: ${isPasswordHashed}`);
  
  let passwordValid = false;
  
  if (isPasswordHashed) {
    try {
      passwordValid = await bcrypt.compare(password, user.password);
      console.log('Resultado de bcrypt.compare:', passwordValid);
    } catch (error) {
      console.error('Error al comparar contraseñas:', error);
    }
  } else {
    // Contraseña en texto plano (no debería ocurrir en producción)
    passwordValid = user.password === password;
    console.log('Comparación de texto plano:', password === user.password);
  }
  
  console.log(`¿Contraseña válida?: ${passwordValid}`);
  
  if (!passwordValid) {
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  }
  
  // Actualizar el campo updatedAt del usuario para seguimiento de actividad
  user.updatedAt = Date.now();
  
  // Actualizar en ambos sistemas
  if (userSource === 'json') {
    // Actualizar en el archivo
    const userIndex = users.findIndex(u => u.username.toLowerCase() === username.toLowerCase());
    if (userIndex !== -1) {
      users[userIndex] = user;
      writeUsers(users);
    }
    
    // Actualizar en OpenSearch
    await saveUserToDB(user);
  } else {
    // Actualizar en OpenSearch
    await saveUserToDB(user);
    
    // Actualizar en el archivo
    const userIndex = users.findIndex(u => u.username.toLowerCase() === username.toLowerCase());
    if (userIndex !== -1) {
      users[userIndex] = user;
    } else {
      users.push(user);
    }
    writeUsers(users);
  }
  
  const token = generateToken(user);
  res.json({ token, role: user.role });
});

// Recuperación de contraseña
app.post('/api/recover-password', async (req, res) => {
  const { username } = req.body;
  
  // Validación básica
  if (!username || username.length < 3 || /\s/.test(username)) {
    return res.status(400).json({ error: 'Usuario no válido' });
  }
  
  try {
    // IMPORTANTE: Siempre buscar primero en users.json ya que es más confiable en este caso
    let user = null;
    let userSource = '';
    
    // Primero buscar en users.json
    const users = readUsers();
    const userIndex = users.findIndex(u => u.username.toLowerCase() === username.toLowerCase());
    
    if (userIndex !== -1) {
      user = users[userIndex];
      userSource = 'json';
      console.log('Usuario encontrado en: JSON');
    } else {
      // Si no se encuentra en JSON, buscar en DB
      user = await getUserFromDB(username.toLowerCase());
      userSource = 'db';
      console.log('Usuario encontrado en: DB');
    }
    
    // Si el usuario existe, generamos el token y enviamos el correo
    if (user) {
      // Generar token seguro (32 caracteres alfanuméricos) usando crypto nativo
      const resetToken = crypto.randomBytes(16).toString('hex');
      
      // Establecer tiempo de expiración (1 hora)
      const resetTokenExpires = Date.now() + 3600000; // 1 hora en milisegundos
      
      console.log('Token generado:', resetToken);
      console.log('Expira en:', new Date(resetTokenExpires));
      
      // Guardar token en el usuario
      user.resetToken = resetToken;
      user.resetTokenExpires = resetTokenExpires;
      
      let tokenSaved = false;
      
      // Guardar el token según la fuente del usuario
      if (userSource === 'json') {
        // Actualizar en users.json
        users[userIndex].resetToken = resetToken;
        users[userIndex].resetTokenExpires = resetTokenExpires;
        
        // Verificar que los valores se hayan establecido correctamente
        console.log('Usuario antes de guardar:', JSON.stringify(users[userIndex], null, 2));
        
        if (writeUsers(users)) {
          console.log(`Token guardado en JSON para ${user.username}`);
          tokenSaved = true;
        } else {
          console.error(`Error al guardar token en JSON para ${user.username}`);
        }
      } else if (userSource === 'db') {
        // Actualizar usuario en la base de datos
        if (await saveUserToDB(user)) {
          console.log(`Token guardado en DB para ${user.username}`);
          tokenSaved = true;
        } else {
          console.error(`Error al guardar token en DB para ${user.username}`);
          
          // Intentar guardar en JSON como fallback
          const fallbackUsers = readUsers();
          const fallbackIndex = fallbackUsers.findIndex(u => u.username.toLowerCase() === user.username.toLowerCase());
          
          if (fallbackIndex !== -1) {
            fallbackUsers[fallbackIndex].resetToken = resetToken;
            fallbackUsers[fallbackIndex].resetTokenExpires = resetTokenExpires;
            
            if (writeUsers(fallbackUsers)) {
              console.log(`Token guardado en JSON (fallback) para ${user.username}`);
              tokenSaved = true;
            }
          }
        }
      }
      
      if (!tokenSaved) {
        console.error(`No se pudo guardar el token para ${user.username}`);
        return res.status(500).json({ error: 'Error al guardar el token de restablecimiento' });
      }
      
      // Construir URL de restablecimiento
      const resetUrl = `${BASE_URL}/reset-password.html?token=${encodeURIComponent(resetToken)}&username=${encodeURIComponent(user.username)}`;
      
      // Determinar el correo de destino
      let emailTo = user.username; // Por defecto, usamos el username como email
      
      // Si el username no parece ser un email, usar email del usuario si existe
      if (!emailTo.includes('@') && user.email) {
        emailTo = user.email;
      }
      
      // Configurar el correo
      const mailOptions = {
        from: EMAIL_FROM,
        to: emailTo,
        subject: 'Restablecimiento de contraseña - ATTACK-SENTINEL',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; background-color: #f9f9f9;">
            <div style="text-align: center; margin-bottom: 20px;">
              <h2 style="color: #343a40; font-weight: bold;">Restablecimiento de Contraseña</h2>
            </div>
            
            <div style="background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
              <p>Hola,</p>
              <p>Has solicitado restablecer tu contraseña en <strong>ATTACK-SENTINEL</strong>.</p>
              <p>Haz clic en el siguiente enlace para crear una nueva contraseña:</p>
              
              <div style="text-align: center; margin: 25px 0;">
                <a href="${resetUrl}" style="display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
                  Restablecer contraseña
                </a>
              </div>
              
              <p>O copia y pega esta URL en tu navegador:</p>
              <p style="background-color: #f5f5f5; padding: 10px; border-radius: 3px; word-break: break-all; font-size: 14px;">
                ${resetUrl}
              </p>
              
              <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee;">
                <p><strong>Importante:</strong> Este enlace expirará en 1 hora.</p>
                <p>Si no solicitaste este restablecimiento, puedes ignorar este correo. Tu cuenta sigue segura.</p>
              </div>
            </div>
            
            <div style="margin-top: 20px; text-align: center; color: #6c757d; font-size: 12px;">
              <p>ATTACK-SENTINEL - Plataforma de análisis de superficie de ataque</p>
              <p>&copy; ${new Date().getFullYear()} ATTACK-SENTINEL. Todos los derechos reservados.</p>
            </div>
          </div>
        `
      };
      
      try {
        // Enviar correo
        await transporter.sendMail(mailOptions);
        console.log(`Correo de recuperación enviado a ${emailTo}`);
      } catch (emailError) {
        console.error('Error al enviar correo de recuperación:', emailError);
        // No devolvemos error al cliente para no revelar información
      }
    }
    
    // Por seguridad, siempre devolvemos el mismo mensaje
    // aunque el usuario no exista, para evitar enumeración de usuarios
    res.json({ 
      success: true, 
      message: 'Si el usuario existe, recibirás un correo con instrucciones para recuperar tu contraseña.' 
    });
  } catch (error) {
    console.error('Error en recuperación de contraseña:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

// Verificar token de restablecimiento
app.post('/api/verify-reset-token', async (req, res) => {
  const { token, username } = req.body;
  
  console.log('Verificando token para:', username);
  console.log('Token recibido:', token);
  
  if (!token || !username) {
    console.log('Token o username faltante');
    return res.json({ valid: false, error: 'Token o username faltante' });
  }
  
  try {
    // IMPORTANTE: Siempre buscar primero en users.json ya que es más confiable en este caso
    let user = null;
    let storage = '';
    
    // Primero buscar en users.json
    const users = readUsers();
    user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
    
    if (user) {
      storage = 'json';
      console.log('Usuario encontrado en: JSON');
    } else {
      // Si no se encuentra en JSON, buscar en DB
      user = await getUserFromDB(username.toLowerCase());
      storage = 'db';
      console.log('Usuario encontrado en: DB');
    }
    
    if (!user) {
      console.log(`Usuario no encontrado: ${username}`);
      return res.json({ valid: false, error: 'Usuario no encontrado' });
    }
    
    console.log('Usuario completo:', JSON.stringify(user, null, 2));
    console.log('Token almacenado:', user.resetToken);
    console.log('Token recibido:', token);
    console.log('Expiración del token:', new Date(user.resetTokenExpires));
    console.log('Token expirado?', user.resetTokenExpires <= Date.now());
    
    // Verificar si el token es válido y no ha expirado
    if (!user.resetToken) {
      console.log('No hay token almacenado para el usuario');
      return res.json({ valid: false, error: 'No hay solicitud de restablecimiento activa para este usuario' });
    }
    
    const tokenMatch = user.resetToken === token;
    const tokenNotExpired = user.resetTokenExpires > Date.now();
    
    console.log('¿Tokens coinciden?', tokenMatch);
    console.log('¿Token no expirado?', tokenNotExpired);
    
    if (tokenMatch && tokenNotExpired) {
      console.log(`Token válido para ${username} (almacenado en ${storage})`);
      return res.json({ valid: true });
    }
    
    let errorReason = '';
    if (!tokenMatch) errorReason += 'Los tokens no coinciden. ';
    if (!tokenNotExpired) errorReason += 'El token ha expirado. ';
    
    console.log(`Token inválido o expirado para ${username}: ${errorReason}`);
    res.json({ valid: false, error: errorReason.trim() });
  } catch (error) {
    console.error('Error verificando token:', error);
    res.json({ valid: false, error: 'Error interno del servidor' });
  }
});

// Restablecer contraseña
app.post('/api/reset-password', async (req, res) => {
  const { token, username, newPassword } = req.body;
  
  console.log('Solicitud de restablecimiento para:', username);
  console.log('Token recibido:', token);
  
  if (!token || !username || !newPassword) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }
  
  // Validar requisitos mínimos de contraseña
  if (newPassword.length < 3 || /\s/.test(newPassword)) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 3 caracteres y no contener espacios' });
  }
  
  try {
    // IMPORTANTE: Siempre buscar primero en users.json ya que es más confiable en este caso
    let user = null;
    let isInDb = false;
    
    // Primero buscar en users.json
    const users = readUsers();
    const index = users.findIndex(u => u.username.toLowerCase() === username.toLowerCase());
    
    if (index !== -1) {
      user = users[index];
      console.log('Usuario encontrado en: JSON');
      console.log('Token almacenado:', user.resetToken);
      console.log('Expiración del token:', new Date(user.resetTokenExpires));
    } else {
      // Si no se encuentra en JSON, buscar en DB
      user = await getUserFromDB(username.toLowerCase());
      isInDb = true;
      console.log('Usuario encontrado en: DB');
      if (user) {
        console.log('Token almacenado en DB:', user.resetToken);
        console.log('Expiración del token en DB:', new Date(user.resetTokenExpires));
      }
    }
    
    // Verificar si el token es válido y no ha expirado
    if (!user) {
      console.log('Usuario no encontrado');
      return res.status(400).json({ error: 'Usuario no encontrado' });
    }
    
    if (user.resetToken !== token) {
      console.log('Token no coincide');
      console.log('Token esperado:', user.resetToken);
      console.log('Token recibido:', token);
      return res.status(400).json({ error: 'Token inválido' });
    }
    
    if (user.resetTokenExpires <= Date.now()) {
      console.log('Token expirado');
      console.log('Expiración:', new Date(user.resetTokenExpires));
      console.log('Ahora:', new Date());
      return res.status(400).json({ error: 'Token expirado' });
    }
    
    // Hash de la nueva contraseña
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    console.log('Nueva contraseña hasheada:', hashedPassword);
    
    // Actualizar contraseña y eliminar token
    user.password = hashedPassword;
    user.resetToken = null;
    user.resetTokenExpires = null;
    user.passwordLastChanged = Date.now(); // Registrar cuándo se cambió la contraseña
    
    // Guardar cambios
    let updated = false;
    
    if (isInDb) {
      console.log('Guardando contraseña en DB');
      updated = await saveUserToDB(user);
      console.log('¿Guardado en DB exitoso?:', updated);
      
      if (!updated) {
        // Intentar guardar en JSON como fallback
        console.log('Intentando guardar en JSON como fallback');
        const fallbackUsers = readUsers();
        const fallbackIndex = fallbackUsers.findIndex(u => u.username.toLowerCase() === username.toLowerCase());
        
        if (fallbackIndex !== -1) {
          fallbackUsers[fallbackIndex].password = hashedPassword;
          fallbackUsers[fallbackIndex].resetToken = null;
          fallbackUsers[fallbackIndex].resetTokenExpires = null;
          fallbackUsers[fallbackIndex].passwordLastChanged = Date.now();
          
          updated = writeUsers(fallbackUsers);
          console.log('¿Guardado en JSON (fallback) exitoso?:', updated);
          
          // Verificación adicional
          if (updated) {
            const checkUsers = readUsers();
            const checkUser = checkUsers.find(u => u.username.toLowerCase() === username.toLowerCase());
            console.log('Verificación de usuario actualizado en JSON:', JSON.stringify(checkUser, null, 2));
          }
        }
      } else {
        // También actualizar en JSON para mantener sincronización
        console.log('Actualizando también en JSON para sincronización');
        const syncUsers = readUsers();
        const syncIndex = syncUsers.findIndex(u => u.username.toLowerCase() === username.toLowerCase());
        
        if (syncIndex !== -1) {
          syncUsers[syncIndex].password = hashedPassword;
          syncUsers[syncIndex].resetToken = null;
          syncUsers[syncIndex].resetTokenExpires = null;
          syncUsers[syncIndex].passwordLastChanged = Date.now();
          
          const syncUpdated = writeUsers(syncUsers);
          console.log('¿Sincronización en JSON exitosa?:', syncUpdated);
        }
      }
    } else {
      // Actualizar en users.json
      console.log('Guardando contraseña en JSON');
      console.log('Índice del usuario en JSON:', index);
      users[index].password = hashedPassword;
      users[index].resetToken = null;
      users[index].resetTokenExpires = null;
      users[index].passwordLastChanged = Date.now();
      
      updated = writeUsers(users);
      console.log('¿Guardado en JSON exitoso?:', updated);
      
      // Verificar que se haya guardado correctamente
      const updatedUsers = readUsers();
      const updatedUser = updatedUsers.find(u => u.username.toLowerCase() === username.toLowerCase());
      console.log('Contraseña guardada en JSON:', updatedUser?.password);
      
      // También actualizar en DB si existe el usuario allí
      try {
        const dbUser = await getUserFromDB(username.toLowerCase());
        if (dbUser) {
          console.log('Actualizando también en DB para sincronización');
          dbUser.password = hashedPassword;
          dbUser.resetToken = null;
          dbUser.resetTokenExpires = null;
          dbUser.passwordLastChanged = Date.now();
          
          const dbUpdated = await saveUserToDB(dbUser);
          console.log('¿Sincronización en DB exitosa?:', dbUpdated);
        }
      } catch (syncError) {
        console.error('Error en sincronización con DB:', syncError);
      }
    }
    
    if (!updated) {
      return res.status(500).json({ error: 'No se pudo actualizar la contraseña' });
    }
    
    console.log(`Contraseña actualizada para ${username}`);
    
    // Enviar correo de confirmación
    try {
      // Determinar el correo de destino
      let emailTo = user.username; // Por defecto, usamos el username como email
      
      // Si el username no parece ser un email, usar email del usuario si existe
      if (!emailTo.includes('@') && user.email) {
        emailTo = user.email;
      }
      
      const mailOptions = {
        from: EMAIL_FROM,
        to: emailTo,
        subject: 'Confirmación de cambio de contraseña - ATTACK-SENTINEL',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; background-color: #f9f9f9;">
            <div style="text-align: center; margin-bottom: 20px;">
              <h2 style="color: #343a40; font-weight: bold;">Contraseña actualizada</h2>
            </div>
            
            <div style="background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
              <p>Hola,</p>
              <p>Tu contraseña ha sido actualizada correctamente en <strong>ATTACK-SENTINEL</strong>.</p>
              <p>Si no realizaste este cambio, por favor contacta inmediatamente al administrador del sistema.</p>
              
              <div style="text-align: center; margin: 25px 0;">
                <a href="${BASE_URL}" style="display: inline-block; padding: 12px 24px; background-color: #28a745; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
                  Iniciar sesión
                </a>
              </div>
            </div>
            
            <div style="margin-top: 20px; text-align: center; color: #6c757d; font-size: 12px;">
              <p>ATTACK-SENTINEL - Plataforma de análisis de superficie de ataque</p>
              <p>&copy; ${new Date().getFullYear()} ATTACK-SENTINEL. Todos los derechos reservados.</p>
            </div>
          </div>
        `
      };
      
      await transporter.sendMail(mailOptions);
      console.log(`Correo de confirmación enviado a ${emailTo}`);
    } catch (emailError) {
      console.error('Error al enviar correo de confirmación:', emailError);
      // No fallamos la petición si el correo no se envía
    }
    
    res.json({ success: true, message: 'Contraseña actualizada correctamente' });
  } catch (error) {
    console.error('Error restableciendo contraseña:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

// Función para obtener un usuario directamente por ID de OpenSearch
async function getUserByIdFromDB(id) {
  try {
    // Verificar que el ID no está vacío
    if (!id) {
      console.error('Error: Se intentó obtener un usuario con ID vacío');
      return null;
    }
    
    await checkUserIndex(); // Asegurar que el índice existe
    
    try {
      const { body } = await searchClient.get({
        index: 'usuarios',
        id: id.toLowerCase()
      });
      
      if (body && body._source) {
        console.log(`Usuario recuperado de DB por ID: ${id}`);
        return {
          ...body._source,
          id: body._id
        };
      }
    } catch (error) {
      // Si el documento no existe, el error es normal
      if (error.meta && error.meta.statusCode === 404) {
        console.log(`Usuario con ID ${id} no encontrado en OpenSearch`);
        return null;
      }
      
      // Para otros errores, lanzar excepción
      console.error(`Error al recuperar usuario por ID ${id}:`, error.message);
      throw error;
    }
    
    return null;
  } catch (error) {
    console.error(`Error al buscar usuario por ID (${id}):`, error.message);
    return null;
  }
}

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
  let user = users.find(u => u.googleId === profile.id || u.username === profile.emails[0].value.toLowerCase());
  if (!user) {
    user = {
      username: profile.emails[0].value.toLowerCase(),
      password: '',
      role: 'user',
      googleId: profile.id
    };
    users.push(user);
    writeUsers(users);
    try {
      await saveUserToDB(user);
    } catch (err) {
      console.error('Error guardando usuario Google en OpenSearch:', err.message);
    }
  } else {
    // Actualiza googleId si no está
    if (!user.googleId) {
      user.googleId = profile.id;
      writeUsers(users);
      try {
        await saveUserToDB(user);
      } catch (err) {
        console.error('Error actualizando usuario Google en OpenSearch:', err.message);
      }
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
        username: req.user.username.toLowerCase(), // <-- SIEMPRE minúsculas
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
      username: req.user.username.toLowerCase(), // <-- SIEMPRE minúsculas
      role: req.user.role
    };
    await saveReport(doc);
    let rows = [];
    // 1. Extraer filas del análisis normal
    if (cfg.name === 'SmapScan_1_0') {
  try {
    let ports = [];
    // ...existing code for ports...
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
    } catch (e) {
      console.error('Error en análisis SmapScan_1_0:', e);
    }
} else if (cfg.name === 'Crt_sh_Transparency_Logs_1_0') {
  try {
      // Extracción robusta de subdominios tras obtener el report
      const certList = report.full?.certobj?.result || report.certobj?.result || [];
      // Dominio objetivo (sin www)
      const mainDomain = target.replace(/^www\./, '').toLowerCase();
      // Solo dominios/subdominios válidos (no IPs ni UUIDs) y que contengan el dominio objetivo
      const domainRegex = /^([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}$/;
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
      const subs = [...new Set(certList
        .flatMap(r => (r.name_value || '').split(/\s+|,|;|\n/))
        .map(s => s.trim().toLowerCase())
        .filter(s => domainRegex.test(s) && !ipRegex.test(s) && s.includes(mainDomain) && s !== mainDomain)
      )];
      rows = subs.map(name => ({ service: 'Subdomain', description: name, details: 'Detectado por crt.sh' }));
      if (!rows.length) {
        rows = [{ service: 'Subdomain', description: 'No se detectaron subdominios.', details: '' }];
      }
    } catch (e) {
      console.error('Error en análisis Crt_sh_Transparency_Logs_1_0:', e);
    }
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
      const cveRegex = /\bCVE-\d{4}-\{4,}\b/gi;
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
    // Generar PDF completo
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
    pdf.fontSize(14).text('Resultados técnicos:', { underline: true });
    if (data.result && Array.isArray(data.result.results) && data.result.results.length > 0) {
      data.result.results.forEach((r, i) => {
        pdf.moveDown(0.5);
        pdf.fontSize(12).text(`${i + 1}. Servicio: ${r.service || '-'}\n   Descripción: ${r.description || '-'}\n   Detalles: ${r.details || '-'}`);
      });
    } else {
      pdf.fontSize(12).text('No hay resultados técnicos.');
    }
    // Adjuntar informe técnico completo (full) aunque no haya resultados técnicos
    if (data.result && data.result.full) {
      pdf.moveDown();
      pdf.fontSize(14).text('Informe técnico completo (JSON):', { underline: true });
      pdf.fontSize(9).text(JSON.stringify(data.result.full, null, 2), { width: 480 });
    }
    // Adjuntar informe AI (Ollama) en la misma página, con formato claro
    let aiReport = '';
    if (data.result && typeof data.result.full === 'object' && data.result.full) {
      aiReport = data.result.full.aiReport || data.result.full.resumenAI || '';
    }
    if (!aiReport && data.result && data.result.aiReport) {
      aiReport = data.result.aiReport;
    }
    if (!aiReport && data.result && data.result.resumenAI) {
      aiReport = data.result.resumenAI;
    }
    if (!aiReport && data.resumenAI) {
      aiReport = data.resumenAI;
    }
    if (aiReport && typeof aiReport === 'string' && aiReport.trim().length > 0) {
      pdf.moveDown();
      pdf.fontSize(14).text('Informe IA (Ollama):', { underline: true });
      pdf.moveDown(0.5);
      pdf.font('Helvetica').fontSize(12).text(aiReport, {
        width: 480,
        lineGap: 4,
        paragraphGap: 8,
        wordWrap: true
      });
    }
    pdf.end();
  } catch (err) {
    res.status(500).json({ error: 'Error generando PDF', detail: err.message });
  }
});

// --- RUTAS DE ADMINISTRACIÓN DE USUARIOS ---

// Middleware para verificar si el usuario es administrador
function adminMiddleware(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acceso denegado. Se requieren permisos de administrador.' });
  }
  next();
}

// Obtener todos los usuarios (solo para administradores)
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    // Obtener usuarios tanto de users.json como de OpenSearch
    const jsonUsers = readUsers();
    const dbUsers = await getAllUsersFromDB();
    
    // Combinar usuarios, priorizando los de JSON
    const dbUsernames = dbUsers.map(u => u.username.toLowerCase());
    const combinedUsers = [...jsonUsers];
    
    // Agregar usuarios de DB que no están en JSON
    for (const dbUser of dbUsers) {
      if (!jsonUsers.some(u => u.username.toLowerCase() === dbUser.username.toLowerCase())) {
        combinedUsers.push(dbUser);
      }
    }
    
    // Verificar la sincronización y realizar acciones necesarias
    for (const user of jsonUsers) {
      if (!dbUsernames.includes(user.username.toLowerCase())) {
        // Usuario en JSON pero no en DB, sincronizar
        await saveUserToDB(user);
      }
    }
    
    res.json(combinedUsers);
  } catch (error) {
    console.error('Error al obtener usuarios:', error);
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});

// Obtener un usuario específico por username
app.get('/api/admin/users/:username', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { username } = req.params;
    
    // Buscar en users.json
    const jsonUsers = readUsers();
    const jsonUser = jsonUsers.find(u => u.username.toLowerCase() === username.toLowerCase());
    
    if (jsonUser) {
      return res.json(jsonUser);
    }
    
    // Si no está en JSON, buscar en OpenSearch
    const dbUser = await getUserFromDB(username.toLowerCase());
    
    if (dbUser) {
      return res.json(dbUser);
    }
    
    res.status(404).json({ error: 'Usuario no encontrado' });
  } catch (error) {
    console.error('Error al obtener usuario:', error);
    res.status(500).json({ error: 'Error al obtener usuario' });
  }
});

// Crear o actualizar usuario
app.post('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const userData = req.body;
    
    if (!userData.username || userData.username.length < 3) {
      return res.status(400).json({ error: 'El nombre de usuario debe tener al menos 3 caracteres' });
    }
    
    // Si se proporciona contraseña y no está hasheada, hash primero
    if (userData.password && !userData.password.startsWith('$2')) {
      userData.password = await bcrypt.hash(userData.password, 10);
    }
    
    // Establecer valores por defecto
    userData.role = userData.role || 'user';
    userData.updatedAt = Date.now();
    
    // Guardar en users.json
    const jsonUsers = readUsers();
    const userIndex = jsonUsers.findIndex(u => u.username.toLowerCase() === userData.username.toLowerCase());
    
    if (userIndex !== -1) {
      // Actualizar usuario existente
      jsonUsers[userIndex] = { ...jsonUsers[userIndex], ...userData };
    } else {
      // Crear nuevo usuario
      userData.createdAt = Date.now();
      jsonUsers.push(userData);
    }
    
    const jsonSaved = writeUsers(jsonUsers);
    
    // Guardar en OpenSearch
    const dbSaved = await saveUserToDB(userData);
    
    if (jsonSaved || dbSaved) {
      res.json({ success: true, message: 'Usuario guardado correctamente' });
    } else {
      res.status(500).json({ error: 'Error al guardar usuario' });
    }
  } catch (error) {
    console.error('Error al guardar usuario:', error);
    res.status(500).json({ error: 'Error al guardar usuario' });
  }
});

// Eliminar usuario
app.delete('/api/admin/users/:username', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { username } = req.params;
    
    // Eliminar de users.json
    const jsonUsers = readUsers();
    const filteredUsers = jsonUsers.filter(u => u.username.toLowerCase() !== username.toLowerCase());
    
    if (filteredUsers.length < jsonUsers.length) {
      writeUsers(filteredUsers);
    }
    
    // Eliminar de OpenSearch
    await deleteUserFromDB(username);
    
    res.json({ success: true, message: 'Usuario eliminado correctamente' });
  } catch (error) {
    console.error('Error al eliminar usuario:', error);
    res.status(500).json({ error: 'Error al eliminar usuario' });
  }
});

// Ruta para obtener todos los análisis (para panel de administrador)
app.get('/api/admin/analyses', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const analyses = await getDecryptedReports({ match_all: {} }, 1000);
    res.json(analyses);
  } catch (error) {
    console.error('Error al obtener análisis:', error);
    res.status(500).json({ error: 'Error al obtener análisis' });
  }
});

// Ruta para eliminar un análisis específico
app.delete('/api/admin/analysis/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    
    await searchClient.delete({
      index: INDEX_NAME,
      id,
      refresh: 'true'
    });
    
    res.json({ success: true, message: 'Análisis eliminado correctamente' });
  } catch (error) {
    console.error('Error al eliminar análisis:', error);
    res.status(500).json({ error: 'Error al eliminar análisis' });
  }
});

// Ruta para actualizar un análisis existente
app.put('/api/admin/analysis/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const analysisData = req.body;
    
    // Validar datos mínimos

    if (!analysisData.target || !analysisData.analyzer) {
      return res.status(400).json({ error: 'Faltan datos obligatorios (target, analyzer)' });
    }
    
    // Encriptar los datos
    const encryptedData = encrypt(JSON.stringify(analysisData));
    
    await searchClient.update({
      index: INDEX_NAME,
      id,
      body: {
        doc: { data: encryptedData }
      },
      refresh: 'true'
    });
    
    res.json({ success: true, message: 'Análisis actualizado correctamente' });
  } catch (error) {
    console.error('Error al actualizar análisis:', error);
    res.status(500).json({ error: 'Error al actualizar análisis' });
  }
});

// Ruta para insertar un nuevo análisis
app.post('/api/admin/analysis', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const analysisData = req.body;
    
    // Validar datos mínimos
    if (!analysisData.target || !analysisData.analyzer || !analysisData.username) {
      return res.status(400).json({ error: 'Faltan datos obligatorios (target, analyzer, username)' });
    }
    
    // Asegurar que la fecha es un string ISO
    if (!analysisData.timestamp) {
      analysisData.timestamp = new Date().toISOString();
    }
    
    // Guardar en OpenSearch
    await saveReport(analysisData);
    
    res.json({ success: true, message: 'Análisis insertado correctamente' });
  } catch (error) {
    console.error('Error al insertar análisis:', error);
    res.status(500).json({ error: 'Error al insertar análisis' });
  }
});

// Ruta para obtener estadísticas del panel de administrador
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    // Obtener todos los análisis
    const analyses = await getDecryptedReports({ match_all: {} }, 1000);
    
    // Calcular estadísticas
    const stats = {
      totalAnalyses: analyses.length,
      activeUsers: new Set(analyses.map(a => a.username)).size,
      types: new Set(analyses.map(a => a.analyzer)).size,
      vulns: analyses.reduce((count, analysis) => {
        // Contar vulnerabilidades en cada análisis
        const results = analysis.result?.results || [];
        return count + results.length;
      }, 0)
    };
    
    res.json(stats);
  } catch (error) {
    console.error('Error al obtener estadísticas:', error);
    res.status(500).json({ error: 'Error al obtener estadísticas' });
  }
});

// --- HEALTH CHECK ---
app.get('/api/health', (req, res) => {
  res.json({ status: 'UP', timestamp: new Date() });
});

// --- RUTAS ESTÁTICAS ---
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send('User-agent: *\nDisallow: /');
});

app.get('/sitemap.xml', (req, res) => {
  res.type('application/xml');
  res.send(`
    <?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap-image/1.1" xmlns:image="http://www.google.com/schemas/sitemap-image">
      <url>
        <loc>${BASE_URL}/</loc>
        <lastmod>${new Date().toISOString()}</lastmod>
        <changefreq>daily</changefreq>
        <priority>1.0</priority>
      </url>
      <url>
        <loc>${BASE_URL}/about.html</loc>
        <lastmod>${new Date().toISOString()}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
      </url>
      <url>
        <loc>${BASE_URL}/contact.html</loc>
        <lastmod>${new Date().toISOString()}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
      </url>
      <url>
        <loc>${BASE_URL}/services.html</loc>
        <lastmod>${new Date().toISOString()}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
      </url>
      <url>
        <loc>${BASE_URL}/auth-success.html</loc>
        <lastmod>${new Date().toISOString()}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
      </url>
    </urlset>
  `);
});

// --- ERRORES 404 Y 500 ---
app.use((req, res, next) => {
  res.status(404).json({ error: 'No encontrado' });
});

app.use((err, req, res, next) => {
  console.error('Error interno del servidor:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// --- INICIAR SERVIDOR ---
app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
  checkIndex();
  checkUserIndex();
});

// Import test routes for OpenSearch
require('./opensearch-test-routes');

// Test endpoint to create a user directly in OpenSearch
app.post('/api/test/create-user-in-opensearch', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { username, password, role } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username and password are required' 
      });
    }
    
    // Create user object
    const timestamp = Date.now();
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = {
      username: username.toLowerCase(),
      password: hashedPassword,
      role: role || 'user',
      createdAt: timestamp,
      updatedAt: timestamp
    };
    
    // Save directly to OpenSearch
    console.log(`Saving test user ${username} directly to OpenSearch...`);
    const result = await saveUserToDB(user);
    
    if (result) {
      // Verify the user was saved
      const savedUser = await getUserFromDB(username.toLowerCase());
      
      if (savedUser) {
        console.log(`Test user ${username} successfully saved to OpenSearch`);
        return res.json({
          success: true,
          message: `User ${username} created successfully in OpenSearch`,
          user: {
            ...savedUser,
            password: '***REDACTED***'
          }
        });
      } else {
        console.error(`Test user ${username} was not found after saving`);
        return res.status(500).json({
          success: false,
          error: 'User was saved but could not be retrieved'
        });
      }
    } else {
      console.error(`Failed to save test user ${username} to OpenSearch`);
      return res.status(500).json({
        success: false,
        error: 'Failed to save user to OpenSearch'
      });
    }
  } catch (error) {
    console.error('Error in test endpoint:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Test endpoint to verify OpenSearch connectivity
app.get('/api/test/opensearch-status', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    console.log('Testing OpenSearch connectivity...');
    
    // Test basic connectivity
    const { body: info } = await searchClient.info();
    
    // Check if users index exists
    const { body: indexExists } = await searchClient.indices.exists({ index: 'usuarios' });
    
    let userCount = 0;
    let usersSample = [];
    
    if (indexExists) {
      // Count users
      const { body: countResult } = await searchClient.count({ index: 'usuarios' });
      userCount = countResult.count;
      
      // Get a sample of users
      if (userCount > 0) {
        const { body: usersResult } = await searchClient.search({
          index: 'usuarios',
          size: 3,
          body: {
            query: { match_all: {} },
            sort: [{ updatedAt: { order: 'desc' } }]
          }
        });
        
        usersSample = usersResult.hits.hits.map(hit => ({
          id: hit._id,
          username: hit._source.username,
          role: hit._source.role,
          createdAt: hit._source.createdAt,
          updatedAt: hit._source.updatedAt
        }));
      }
    }
    
    return res.json({
      success: true,
      opensearch: {
        version: info.version.number,
        clusterName: info.cluster_name,
        status: 'connected'
      },
      usersIndex: {
        exists: indexExists,
        userCount,
        recentUsers: usersSample
      }
    });
  } catch (error) {
    console.error('Error checking OpenSearch status:', error);
    return res.status(500).json({
      success: false,
      error: error.message,
      status: 'disconnected'
    });
  }
});