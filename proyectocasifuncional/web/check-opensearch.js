// Script de diagnóstico para probar la funcionalidad de OpenSearch
const { Client } = require('@opensearch-project/opensearch');
const fs = require('fs');
const path = require('path');

// Configuración
const OPENSEARCH_HOST = 'http://localhost:9200';
const USERS_FILE = path.join(__dirname, 'users.json');

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

// Función para verificar si el índice de usuarios existe
async function checkUserIndex() {
  try {
    console.log(`Verificando si el índice 'usuarios' existe en ${OPENSEARCH_HOST}...`);
    const { body: exists } = await searchClient.indices.exists({ index: 'usuarios' });
    
    if (exists) {
      console.log('✅ El índice de usuarios existe');
      
      // Obtener estadísticas del índice
      const { body: stats } = await searchClient.indices.stats({ index: 'usuarios' });
      console.log(`   - Documentos: ${stats.indices.usuarios.total.docs.count}`);
      console.log(`   - Tamaño: ${stats.indices.usuarios.total.store.size}`);
      
      // Obtener mapeo
      const { body: mapping } = await searchClient.indices.getMapping({ index: 'usuarios' });
      console.log('   - Campos configurados:', Object.keys(mapping.usuarios.mappings.properties).join(', '));
      
      return true;
    } else {
      console.log('❌ El índice de usuarios NO existe');
      return false;
    }
  } catch (error) {
    console.error('❌ Error al verificar el índice de usuarios:', error.message);
    return false;
  }
}

// Función para verificar la conectividad con OpenSearch
async function checkOpenSearchConnection() {
  try {
    console.log(`Verificando conexión a OpenSearch en ${OPENSEARCH_HOST}...`);
    const { body: info } = await searchClient.info();
    
    console.log('✅ Conexión a OpenSearch exitosa');
    console.log(`   - Versión: ${info.version.number}`);
    console.log(`   - Nombre del clúster: ${info.cluster_name}`);
    
    return true;
  } catch (error) {
    console.error('❌ Error de conexión a OpenSearch:', error.message);
    return false;
  }
}

// Función para contar usuarios en OpenSearch
async function countUsersInDB() {
  try {
    console.log('Contando usuarios en OpenSearch...');
    const { body: count } = await searchClient.count({ index: 'usuarios' });
    
    console.log(`✅ Total de usuarios en OpenSearch: ${count.count}`);
    return count.count;
  } catch (error) {
    console.error('❌ Error al contar usuarios en OpenSearch:', error.message);
    return -1;
  }
}

// Función para obtener algunos usuarios de muestra
async function getSampleUsers(size = 5) {
  try {
    console.log(`Obteniendo ${size} usuarios de muestra de OpenSearch...`);
    const { body } = await searchClient.search({
      index: 'usuarios',
      size,
      body: {
        query: { match_all: {} },
        sort: [{ updatedAt: { order: 'desc' } }]
      }
    });
    
    if (body.hits && body.hits.hits && body.hits.hits.length > 0) {
      console.log('✅ Usuarios recuperados exitosamente');
      
      // Mostrar usuarios con contraseñas ocultas
      body.hits.hits.forEach((hit, index) => {
        const user = hit._source;
        console.log(`\nUsuario ${index + 1}:`);
        console.log(`   - ID: ${hit._id}`);
        console.log(`   - Username: ${user.username}`);
        console.log(`   - Role: ${user.role}`);
        console.log(`   - Email: ${user.email || 'No especificado'}`);
        console.log(`   - Creado: ${new Date(user.createdAt).toLocaleString()}`);
        console.log(`   - Actualizado: ${new Date(user.updatedAt).toLocaleString()}`);
      });
      
      return body.hits.hits.length;
    } else {
      console.log('❌ No se encontraron usuarios en OpenSearch');
      return 0;
    }
  } catch (error) {
    console.error('❌ Error al obtener usuarios de muestra:', error.message);
    return -1;
  }
}

// Función para comparar usuarios entre archivo y OpenSearch
async function compareUserStores() {
  try {
    console.log('Comparando usuarios entre archivo JSON y OpenSearch...');
    
    // Leer usuarios del archivo
    const fileUsers = readUsers();
    console.log(`Usuarios en archivo JSON: ${fileUsers.length}`);
    
    // Contar usuarios en OpenSearch
    const dbCount = await countUsersInDB();
    if (dbCount < 0) {
      console.log('❌ No se pudo obtener el conteo de usuarios en OpenSearch');
      return false;
    }
    
    if (fileUsers.length === dbCount) {
      console.log('✅ La cantidad de usuarios coincide entre ambos almacenamientos');
    } else {
      console.log(`⚠️ Diferencia en la cantidad de usuarios: ${fileUsers.length} en archivo vs ${dbCount} en OpenSearch`);
    }
    
    // Obtener todos los usuarios de OpenSearch para comparación
    const { body } = await searchClient.search({
      index: 'usuarios',
      size: 1000,
      body: { query: { match_all: {} } }
    });
    
    const dbUsers = body.hits.hits.map(hit => ({
      ...hit._source,
      id: hit._id
    }));
    
    // Crear conjuntos de nombres de usuario para comparación rápida
    const fileUsernames = new Set(fileUsers.map(u => u.username.toLowerCase()));
    const dbUsernames = new Set(dbUsers.map(u => u.username.toLowerCase()));
    
    // Verificar usuarios en archivo que no están en DB
    const missingInDb = [...fileUsernames].filter(u => !dbUsernames.has(u));
    if (missingInDb.length > 0) {
      console.log(`⚠️ ${missingInDb.length} usuarios en archivo pero no en OpenSearch:`, missingInDb);
    } else {
      console.log('✅ Todos los usuarios del archivo están en OpenSearch');
    }
    
    // Verificar usuarios en DB que no están en archivo
    const missingInFile = [...dbUsernames].filter(u => !fileUsernames.has(u));
    if (missingInFile.length > 0) {
      console.log(`⚠️ ${missingInFile.length} usuarios en OpenSearch pero no en archivo:`, missingInFile);
    } else {
      console.log('✅ Todos los usuarios de OpenSearch están en el archivo');
    }
    
    return true;
  } catch (error) {
    console.error('❌ Error al comparar almacenamientos de usuarios:', error.message);
    return false;
  }
}

// Función principal de diagnóstico
async function runDiagnostics() {
  console.log('=== DIAGNÓSTICO DEL SISTEMA DE USUARIOS EN OPENSEARCH ===\n');
  
  try {
    // Verificar conexión a OpenSearch
    const connected = await checkOpenSearchConnection();
    if (!connected) {
      console.error('\n❌ No se pudo conectar a OpenSearch. Verifique que el servicio esté ejecutándose.');
      return;
    }
    
    // Verificar índice de usuarios
    const indexExists = await checkUserIndex();
    if (!indexExists) {
      console.log('\n⚠️ El índice de usuarios no existe. Intente acceder a la aplicación para crearlo automáticamente.');
    }
    
    // Contar usuarios en cada almacenamiento
    await compareUserStores();
    
    // Mostrar algunos usuarios de muestra si hay alguno
    await getSampleUsers(3);
    
    console.log('\n=== DIAGNÓSTICO COMPLETADO ===');
  } catch (error) {
    console.error('\n❌ Error durante el diagnóstico:', error);
  }
}

// Ejecutar diagnóstico
runDiagnostics()
  .then(() => {
    console.log('\nPara solucionar problemas de sincronización, puede utilizar los siguientes endpoints:');
    console.log('1. GET /api/admin/check-user-db - Verificar integridad de la base de datos');
    console.log('2. POST /api/admin/migrate-users - Migrar usuarios del archivo a OpenSearch');
    console.log('3. POST /api/admin/sync-users - Sincronizar usuarios entre archivo y OpenSearch');
  })
  .catch(err => {
    console.error('Error ejecutando diagnóstico:', err);
  });
