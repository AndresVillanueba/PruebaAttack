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
    const dbUsers = await getAllUsersFromDB();
    res.json(dbUsers);
  } catch (error) {
    console.error('Error al obtener usuarios:', error);
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});

// Obtener un usuario específico por username
app.get('/api/admin/users/:username', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { username } = req.params;
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
    if (userData.password && !userData.password.startsWith('$2')) {
      userData.password = await bcrypt.hash(userData.password, 10);
    }
    userData.role = userData.role || 'user';
    userData.updatedAt = Date.now();
    if (!userData.createdAt) userData.createdAt = Date.now();
    const dbSaved = await saveUserToDB(userData);
    if (dbSaved) {
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

// Ruta para reportar un análisis existente (por falta de permisos, etc.)
app.put('/api/admin/analysis/:id/report', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const reportData = req.body;
    if (!reportData.reason || !reportData.reportedBy) {
      return res.status(400).json({ error: 'Faltan datos obligatorios (reason, reportedBy)' });
    }
    const { body } = await searchClient.get({
      index: INDEX_NAME,
      id
    });
    const currentData = JSON.parse(decrypt(body._source.data));
    currentData.reported = true;
    currentData.reportReason = reportData.reason;
    currentData.reportedBy = reportData.reportedBy;
    currentData.reportedAt = new Date().toISOString();
    const encryptedData = encrypt(JSON.stringify(currentData));
    await searchClient.update({
      index: INDEX_NAME,
      id,
      body: {
        doc: {
          data: encryptedData,
          reported: true
        }
      },
      refresh: 'true'
    });
    res.json({ success: true, message: 'Análisis reportado correctamente' });
  } catch (error) {
    console.error('Error al reportar análisis:', error);
    res.status(500).json({ error: 'Error al reportar análisis' });
  }
});

// Ruta para insertar un nuevo análisis
app.post('/api/admin/analysis', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const analysisData = req.body;
    if (!analysisData.target || !analysisData.analyzer || !analysisData.username) {
      return res.status(400).json({ error: 'Faltan datos obligatorios (target, analyzer, username)' });
    }
    if (!analysisData.timestamp) {
      analysisData.timestamp = new Date().toISOString();
    }
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
    const analyses = await getDecryptedReports({ match_all: {} }, 1000);
    const stats = {
      totalAnalyses: analyses.length,
      activeUsers: new Set(analyses.map(a => a.username)).size,
      types: new Set(analyses.map(a => a.analyzer)).size,
      vulns: analyses.reduce((count, analysis) => {
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

// Obtener historial de análisis de un usuario específico
app.get('/api/admin/users/:username/analyses', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { username } = req.params;
    const userAnalyses = await getDecryptedReports({
      term: {
        "username.keyword": username
      }
    }, 1000);
    res.json(userAnalyses);
  } catch (error) {
    console.error('Error al obtener historial de análisis:', error);
    res.status(500).json({ error: 'Error al obtener historial de análisis' });
  }
});

// --- RUTAS DE REGISTRO DE USUARIO ---
app.post('/api/register', async (req, res) => {
  try {
    const userData = req.body;
    if (!userData.username || userData.username.length < 3) {
      return res.status(400).json({ error: 'El nombre de usuario debe tener al menos 3 caracteres' });
    }
    if (!userData.password || userData.password.length < 6) {
      return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
    }
    userData.password = await bcrypt.hash(userData.password, 10);
    userData.role = 'user';
    userData.createdAt = Date.now();
    userData.updatedAt = Date.now();
    const dbSaved = await saveUserToDB(userData);
    if (dbSaved) {
      res.json({ success: true, message: 'Usuario registrado correctamente' });
    } else {
      res.status(500).json({ error: 'Error al registrar usuario' });
    }
  } catch (error) {
    console.error('Error al registrar usuario:', error);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});
