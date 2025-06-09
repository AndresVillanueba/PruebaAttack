// Script para regenerar y reconstruir el índice de usuarios en OpenSearch
// Este script debe ejecutarse con Node.js
// Nota: Es recomendable hacer una copia de seguridad de los usuarios antes de ejecutar esto

require('dotenv').config();
const { Client } = require('@opensearch-project/opensearch');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');

// Configuración
const OPENSEARCH_HOST = process.env.OPENSEARCH_HOST || 'http://localhost:9200';
const USERS_FILE = path.join(__dirname, 'users.json');
const USERS_BACKUP_FILE = path.join(__dirname, 'users.backup.json');

// Cliente OpenSearch
const searchClient = new Client({ node: OPENSEARCH_HOST });

// Función para leer usuarios del archivo JSON
function readUsers() {
  try {
    if (!fs.existsSync(USERS_FILE)) {
      console.log('El archivo users.json no existe');
      return [];
    }
    const data = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error al leer users.json:', error);
    return [];
  }
}

// Función para escribir usuarios al archivo JSON
function writeUsers(users) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    return true;
  } catch (error) {
    console.error('Error al escribir users.json:', error);
    return false;
  }
}

// Función para hacer backup de usuarios
function backupUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      fs.copyFileSync(USERS_FILE, USERS_BACKUP_FILE);
      console.log(`✅ Backup de usuarios creado en ${USERS_BACKUP_FILE}`);
      return true;
    } else {
      console.error(`❌ No se encontró el archivo ${USERS_FILE} para hacer backup`);
      return false;
    }
  } catch (error) {
    console.error('Error al hacer backup de usuarios:', error);
    return false;
  }
}

// Función para verificar si un usuario existe en OpenSearch
async function userExistsInDB(username) {
  try {
    const { body } = await searchClient.exists({
      index: 'usuarios',
      id: username.toLowerCase()
    });
    return body;
  } catch (error) {
    console.error(`Error al verificar si existe el usuario ${username} en OpenSearch:`, error.message);
    return false;
  }
}

// Función para guardar un usuario en OpenSearch
async function saveUserToDB(user) {
  try {
    // Extraer todos los campos relevantes del usuario
    const userToSave = {
      username: user.username.toLowerCase(),
      password: user.password,
      role: user.role || 'user',
      googleId: user.googleId || null,
      resetToken: user.resetToken || null,
      resetTokenExpires: user.resetTokenExpires || null,
      passwordLastChanged: user.passwordLastChanged || null,
      email: user.email || null,
      createdAt: user.createdAt || Date.now(),
      updatedAt: Date.now()
    };
    
    // Usar el username como _id para evitar duplicados y permitir upsert
    const response = await searchClient.index({
      index: 'usuarios',
      id: user.username.toLowerCase(),
      body: userToSave,
      refresh: 'true'
    });
    
    return true;
  } catch (error) {
    console.error(`Error al guardar usuario ${user.username} en OpenSearch:`, error.message);
    return false;
  }
}

// Función para eliminar el índice de usuarios
async function deleteUsersIndex() {
  try {
    const { body: exists } = await searchClient.indices.exists({ index: 'usuarios' });
    
    if (exists) {
      console.log('Eliminando índice de usuarios...');
      const { body } = await searchClient.indices.delete({ index: 'usuarios' });
      console.log('✅ Índice de usuarios eliminado correctamente');
      return true;
    } else {
      console.log('El índice de usuarios no existe, no hay nada que eliminar');
      return false;
    }
  } catch (error) {
    console.error('Error al eliminar índice de usuarios:', error.message);
    return false;
  }
}

// Función para crear el índice de usuarios
async function createUsersIndex() {
  try {
    const { body: exists } = await searchClient.indices.exists({ index: 'usuarios' });
    
    if (!exists) {
      console.log('Creando índice de usuarios...');
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
      console.log('✅ Índice de usuarios creado correctamente');
      return true;
    } else {
      console.log('El índice de usuarios ya existe');
      return false;
    }
  } catch (error) {
    console.error('Error al crear índice de usuarios:', error.message);
    return false;
  }
}

// Función para migrar usuarios desde el archivo JSON a OpenSearch
async function migrateUsersToOpenSearch() {
  try {
    console.log('Migrando usuarios desde archivo JSON a OpenSearch...');
    
    // Leer usuarios del archivo JSON
    const users = readUsers();
    console.log(`Se encontraron ${users.length} usuarios en el archivo JSON`);
    
    // Preparar para contar éxitos y fallos
    let successCount = 0;
    let failCount = 0;
    
    // Migrar cada usuario
    for (const user of users) {
      try {
        // Validar campos obligatorios
        if (!user.username) {
          console.error('Usuario sin nombre de usuario, omitiendo');
          failCount++;
          continue;
        }
        
        // Añadir campos de timestamp si no existen
        if (!user.createdAt) user.createdAt = Date.now();
        if (!user.updatedAt) user.updatedAt = Date.now();
        
        // Guardar en OpenSearch
        const saveResult = await saveUserToDB(user);
        
        if (saveResult) {
          successCount++;
          console.log(`✅ Usuario ${user.username} migrado correctamente`);
        } else {
          failCount++;
          console.error(`❌ Error al migrar usuario ${user.username}`);
        }
      } catch (err) {
        failCount++;
        console.error(`❌ Error al migrar usuario ${user.username}:`, err.message);
      }
    }
    
    console.log('Migración de usuarios completada');
    console.log(`✅ Éxitos: ${successCount}, ❌ Fallos: ${failCount}`);
    
    return {
      success: true,
      total: users.length,
      migrated: successCount,
      failed: failCount
    };
  } catch (error) {
    console.error('Error en la migración de usuarios:', error.message);
    return {
      success: false,
      error: error.message
    };
  }
}

// Función principal: Regenerar el índice de usuarios
async function regenerateUsersIndex() {
  console.log('=== REGENERACIÓN DEL ÍNDICE DE USUARIOS EN OPENSEARCH ===\n');
  
  try {
    // Paso 1: Hacer backup de usuarios
    console.log('Paso 1: Haciendo backup de usuarios...');
    const backupCreated = backupUsers();
    if (!backupCreated) {
      console.error('❌ No se pudo crear el backup de usuarios. Abortando por seguridad.');
      return;
    }
    
    // Paso 2: Eliminar el índice actual
    console.log('\nPaso 2: Eliminando índice actual...');
    await deleteUsersIndex();
    
    // Paso 3: Crear nuevo índice
    console.log('\nPaso 3: Creando nuevo índice...');
    await createUsersIndex();
    
    // Paso 4: Migrar usuarios desde el archivo JSON
    console.log('\nPaso 4: Migrando usuarios desde archivo JSON...');
    const migrationResult = await migrateUsersToOpenSearch();
    
    console.log('\n=== PROCESO COMPLETADO ===');
    if (migrationResult.success) {
      console.log(`✅ Se migraron ${migrationResult.migrated} de ${migrationResult.total} usuarios al nuevo índice`);
      if (migrationResult.failed > 0) {
        console.log(`⚠️ ${migrationResult.failed} usuarios no pudieron ser migrados`);
      }
    } else {
      console.error(`❌ Error en la migración: ${migrationResult.error}`);
    }
    
  } catch (error) {
    console.error('\n❌ Error durante el proceso de regeneración:', error.message);
  }
}

// Ejecutar la función principal
regenerateUsersIndex()
  .then(() => {
    console.log('\nPara verificar el estado del índice, ejecute:');
    console.log('  node check-opensearch.js');
  })
  .catch(err => {
    console.error('Error ejecutando regeneración:', err);
  });
