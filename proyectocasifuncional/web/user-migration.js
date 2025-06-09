// Función para migrar usuarios desde el archivo JSON a OpenSearch
async function migrateUsersToOpenSearch() {
  try {
    console.log('Iniciando migración de usuarios a OpenSearch...');
    
    // Leer usuarios del archivo JSON
    const users = readUsers();
    console.log(`Se encontraron ${users.length} usuarios en el archivo JSON`);
    
    // Preparar para contar éxitos y fallos
    let successCount = 0;
    let failCount = 0;
    let skippedCount = 0;
    let errors = [];
    
    // Asegurar que el índice existe
    await checkUserIndex();
    
    // Verificar usuarios existentes en OpenSearch para evitar duplicados
    const existingUsers = await getAllUsersFromDB(1000);
    const existingUsernames = new Set(existingUsers.map(u => u.username.toLowerCase()));
    
    console.log(`Se encontraron ${existingUsernames.size} usuarios existentes en OpenSearch`);
    
    // Migrar cada usuario
    for (const user of users) {
      try {
        const username = user.username.toLowerCase();
        
        // Verificar si el usuario ya existe en OpenSearch
        if (existingUsernames.has(username)) {
          // Verificar si necesita actualización basado en timestamps
          const existingUser = existingUsers.find(u => u.username.toLowerCase() === username);
          
          if (existingUser && user.updatedAt && existingUser.updatedAt && user.updatedAt <= existingUser.updatedAt) {
            console.log(`Usuario ${username} ya existe en OpenSearch con datos más recientes, omitiendo`);
            skippedCount++;
            continue;
          }
          
          console.log(`Usuario ${username} ya existe en OpenSearch pero tiene datos desactualizados, actualizando`);
        }
        
        // Añadir campos de timestamp si no existen
        if (!user.createdAt) user.createdAt = Date.now();
        if (!user.updatedAt) user.updatedAt = Date.now();
        
        // Guardar en OpenSearch
        const saveResult = await saveUserToDB(user);
        
        if (saveResult) {
          successCount++;
          console.log(`Usuario ${username} migrado correctamente`);
        } else {
          failCount++;
          errors.push({ username, error: 'Error al guardar en OpenSearch' });
          console.error(`Error al migrar usuario ${username}`);
        }
      } catch (err) {
        failCount++;
        errors.push({ username: user.username, error: err.message });
        console.error(`Error al migrar usuario ${user.username}:`, err);
      }
    }
    
    console.log('Migración de usuarios completada');
    console.log(`Éxitos: ${successCount}, Omitidos: ${skippedCount}, Fallos: ${failCount}`);
    
    return {
      success: true,
      total: users.length,
      migrated: successCount,
      skipped: skippedCount,
      failed: failCount,
      errors: errors
    };
  } catch (error) {
    console.error('Error en la migración de usuarios:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Ruta para migrar usuarios a OpenSearch
app.post('/api/admin/migrate-users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await migrateUsersToOpenSearch();
    res.json(result);
  } catch (error) {
    console.error('Error en migración de usuarios:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Ruta para obtener todos los usuarios desde OpenSearch
app.get('/api/admin/users-db', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await getAllUsersFromDB(1000);
    
    // Eliminar contraseñas por seguridad
    const sanitizedUsers = users.map(user => {
      const { password, ...rest } = user;
      return rest;
    });
    
    res.json(sanitizedUsers);
  } catch (error) {
    console.error('Error al obtener usuarios desde OpenSearch:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Ruta para sincronizar usuarios entre el archivo JSON y OpenSearch
app.post('/api/admin/sync-users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    console.log('Iniciando sincronización bidireccional de usuarios...');
    
    // Leer usuarios del archivo JSON
    const fileUsers = readUsers();
    console.log(`Se encontraron ${fileUsers.length} usuarios en el archivo JSON`);
    
    // Obtener usuarios de OpenSearch
    const dbUsers = await getAllUsersFromDB(1000);
    console.log(`Se encontraron ${dbUsers.length} usuarios en OpenSearch`);
    
    const result = {
      added: {
        toFile: [],
        toDb: []
      },
      updated: {
        inFile: [],
        inDb: []
      },
      errors: []
    };
    
    // Mapear usuarios de la base de datos por nombre de usuario
    const dbUserMap = {};
    dbUsers.forEach(user => {
      dbUserMap[user.username.toLowerCase()] = user;
    });
    
    // Mapear usuarios del archivo por nombre de usuario
    const fileUserMap = {};
    fileUsers.forEach(user => {
      fileUserMap[user.username.toLowerCase()] = user;
    });
    
    // PASO 1: Sincronizar desde el archivo a la base de datos
    console.log('Sincronizando desde archivo JSON a OpenSearch...');
    for (const fileUser of fileUsers) {
      try {
        const username = fileUser.username.toLowerCase();
        
        // Asegurar que tiene timestamps
        if (!fileUser.createdAt) fileUser.createdAt = Date.now();
        if (!fileUser.updatedAt) fileUser.updatedAt = Date.now();
        
        if (dbUserMap[username]) {
          // El usuario existe en ambos lugares, actualizar solo si es necesario
          const dbUser = dbUserMap[username];
          
          // Si el usuario en el archivo tiene datos más recientes
          if (!dbUser.updatedAt || fileUser.updatedAt > dbUser.updatedAt) {
            console.log(`Actualizando usuario ${username} en OpenSearch con datos más recientes del archivo`);
            await saveUserToDB(fileUser);
            result.updated.inDb.push(username);
          }
        } else {
          // El usuario existe en el archivo pero no en la base de datos
          console.log(`Añadiendo usuario ${username} a OpenSearch desde el archivo`);
          await saveUserToDB(fileUser);
          result.added.toDb.push(username);
        }
      } catch (err) {
        result.errors.push({
          username: fileUser.username,
          operation: 'sync_to_db',
          error: err.message
        });
        console.error(`Error al sincronizar ${fileUser.username} a OpenSearch:`, err.message);
      }
    }
    
    // PASO 2: Sincronizar desde la base de datos al archivo
    console.log('Sincronizando desde OpenSearch a archivo JSON...');
    let newFileUsers = [...fileUsers]; // Copia para no modificar durante la iteración
    let fileModified = false;
    
    for (const dbUser of dbUsers) {
      try {
        const username = dbUser.username.toLowerCase();
        
        if (!fileUserMap[username]) {
          // El usuario existe en la base de datos pero no en el archivo
          console.log(`Añadiendo usuario ${username} al archivo desde OpenSearch`);
          newFileUsers.push(dbUser);
          result.added.toFile.push(username);
          fileModified = true;
        } else {
          // El usuario existe en ambos lugares, verificar cuál es más reciente
          const fileUser = fileUserMap[username];
          
          // Si el usuario en la DB tiene datos más recientes
          if (dbUser.updatedAt && (!fileUser.updatedAt || dbUser.updatedAt > fileUser.updatedAt)) {
            console.log(`Actualizando usuario ${username} en el archivo con datos más recientes de OpenSearch`);
            // Reemplazar el usuario en el archivo
            const index = newFileUsers.findIndex(u => u.username.toLowerCase() === username);
            if (index !== -1) {
              newFileUsers[index] = { ...dbUser };
              result.updated.inFile.push(username);
              fileModified = true;
            }
          }
        }
      } catch (err) {
        result.errors.push({
          username: dbUser.username,
          operation: 'sync_to_file',
          error: err.message
        });
        console.error(`Error al sincronizar ${dbUser.username} al archivo:`, err.message);
      }
    }
    
    // Guardar el archivo actualizado solo si hubo cambios
    if (fileModified) {
      console.log('Guardando cambios en el archivo JSON...');
      const writeSuccess = writeUsers(newFileUsers);
      if (!writeSuccess) {
        result.errors.push({
          operation: 'write_file',
          error: 'Error al escribir el archivo users.json'
        });
      }
    } else {
      console.log('No se detectaron cambios en el archivo JSON, omitiendo escritura');
    }
    
    console.log('Sincronización de usuarios completada');
    console.log(`Resumen: ${result.added.toDb.length} añadidos a DB, ${result.updated.inDb.length} actualizados en DB`);
    console.log(`         ${result.added.toFile.length} añadidos al archivo, ${result.updated.inFile.length} actualizados en archivo`);
    console.log(`         ${result.errors.length} errores`);
    
    res.json({
      success: true,
      ...result,
      summary: {
        addedToDb: result.added.toDb.length,
        updatedInDb: result.updated.inDb.length,
        addedToFile: result.added.toFile.length,
        updatedInFile: result.updated.inFile.length,
        errors: result.errors.length
      }
    });
  } catch (error) {
    console.error('Error en sincronización de usuarios:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Función para verificar la integridad de la base de datos de usuarios
async function checkUserDbIntegrity() {
  try {
    console.log('Verificando integridad de la base de datos de usuarios...');
    
    // Comprobar que el índice existe
    const indexExists = await checkUserIndex();
    if (!indexExists) {
      return {
        success: false,
        error: 'El índice de usuarios no existe o no se pudo verificar'
      };
    }
    
    // Leer usuarios del archivo JSON
    const fileUsers = readUsers();
    console.log(`Se encontraron ${fileUsers.length} usuarios en el archivo JSON`);
    
    // Obtener usuarios de OpenSearch
    const dbUsers = await getAllUsersFromDB(1000);
    console.log(`Se encontraron ${dbUsers.length} usuarios en OpenSearch`);
    
    // Analizar diferencias
    const fileUsernames = new Set(fileUsers.map(u => u.username.toLowerCase()));
    const dbUsernames = new Set(dbUsers.map(u => u.username.toLowerCase()));
    
    // Usuarios que están en el archivo pero no en DB
    const missingInDb = [...fileUsernames].filter(username => !dbUsernames.has(username));
    
    // Usuarios que están en DB pero no en el archivo
    const missingInFile = [...dbUsernames].filter(username => !fileUsernames.has(username));
    
    // Usuarios en ambos sistemas pero con posibles inconsistencias
    const commonUsernames = [...fileUsernames].filter(username => dbUsernames.has(username));
    const inconsistentUsers = [];
    
    // Verificar inconsistencias en usuarios comunes
    for (const username of commonUsernames) {
      const fileUser = fileUsers.find(u => u.username.toLowerCase() === username);
      const dbUser = dbUsers.find(u => u.username.toLowerCase() === username);
      
      // Comparar campos clave
      const issues = [];
      
      // Comparar role
      if (fileUser.role !== dbUser.role) {
        issues.push(`role: "${fileUser.role}" vs "${dbUser.role}"`);
      }
      
      // Verificar timestamps
      if (fileUser.updatedAt && dbUser.updatedAt && 
          Math.abs(fileUser.updatedAt - dbUser.updatedAt) > 1000) { // 1 segundo de diferencia
        issues.push(`updatedAt: ${new Date(fileUser.updatedAt).toISOString()} vs ${new Date(dbUser.updatedAt).toISOString()}`);
      }
      
      if (issues.length > 0) {
        inconsistentUsers.push({
          username,
          issues
        });
      }
    }
    
    return {
      success: true,
      stats: {
        fileUsers: fileUsers.length,
        dbUsers: dbUsers.length,
        missingInDb: missingInDb.length,
        missingInFile: missingInFile.length,
        inconsistentUsers: inconsistentUsers.length
      },
      missingInDb,
      missingInFile,
      inconsistentUsers
    };
  } catch (error) {
    console.error('Error al verificar integridad de la base de datos:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Ruta para verificar la integridad de la base de datos de usuarios
app.get('/api/admin/check-user-db', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await checkUserDbIntegrity();
    res.json(result);
  } catch (error) {
    console.error('Error al verificar la base de datos de usuarios:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Ruta para eliminar un usuario (tanto de OpenSearch como del archivo)
app.delete('/api/admin/users/:username', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const username = req.params.username.toLowerCase();
    
    if (username === 'admin') {
      return res.status(403).json({ 
        success: false, 
        error: 'No se puede eliminar el usuario admin' 
      });
    }
    
    console.log(`Eliminando usuario ${username}...`);
    
    // Eliminar de OpenSearch
    const dbDeleteSuccess = await deleteUserFromDB(username);
    
    // Eliminar del archivo
    const users = readUsers();
    const filteredUsers = users.filter(u => u.username.toLowerCase() !== username);
    const fileDeleteSuccess = writeUsers(filteredUsers);
    
    if (dbDeleteSuccess || fileDeleteSuccess) {
      res.json({ 
        success: true,
        message: `Usuario ${username} eliminado correctamente`,
        dbDelete: dbDeleteSuccess,
        fileDelete: fileDeleteSuccess
      });
    } else {
      res.status(404).json({ 
        success: false, 
        error: `Usuario ${username} no encontrado o no se pudo eliminar` 
      });
    }
  } catch (error) {
    console.error(`Error al eliminar usuario:`, error);
    res.status(500).json({ success: false, error: error.message });
  }
});
