require('dotenv').config();
const { Client } = require('@opensearch-project/opensearch');
const fs = require('fs');
const path = require('path');

const OPENSEARCH_HOST = 'http://localhost:9200';
const USERS_FILE = path.join(__dirname, 'users.json');

const client = new Client({ 
    node: OPENSEARCH_HOST,
    ssl: {
        rejectUnauthorized: false
    }
});

async function deleteUser(username) {
    try {
        const response = await client.delete({
            index: 'usuarios',
            id: username.toLowerCase(),
            refresh: true
        });
        console.log(`Usuario ${username} eliminado de OpenSearch`);
        return true;
    } catch (error) {
        console.error(`Error al eliminar usuario ${username}:`, error.message);
        return false;
    }
}

const { correlateServiceWithMitre } = require('./mitre_correlation');

async function saveAnalysis(username, analysisType, result) {
    try {
        // Realizar correlación MITRE si hay servicios o tecnologías detectadas
        let mitreCorrelations = [];
        if (result.services || result.technologies || result.detected_services) {
            const servicesToAnalyze = [...(result.services || []), ...(result.technologies || []), ...(result.detected_services || [])];
            for (const service of servicesToAnalyze) {
                const correlations = await correlateServiceWithMitre(service);
                if (correlations && correlations.length > 0) {
                    mitreCorrelations.push({
                        service: service,
                        techniques: correlations
                    });
                }
            }
        }

        const analysis = {
            username: username.toLowerCase(),
            timestamp: new Date().toISOString(),
            analysis_type: analysisType,
            result: result,
            mitre_correlations: mitreCorrelations,
            status: 'completed'
        };

        await client.index({
            index: 'analisis',
            body: analysis,
            refresh: true
        });

        console.log(`Análisis guardado para el usuario ${username}`);
        return true;
    } catch (error) {
        console.error(`Error al guardar el análisis para ${username}:`, error.message);
        return false;
    }
}

async function syncUsers() {
    console.log('Iniciando proceso de sincronización...');
    try {
        // Leer usuarios del archivo JSON
        const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        console.log(`Leyendo ${users.length} usuarios del archivo users.json`);

        // Asegurarse de que el índice de usuarios existe
        const indexExists = await client.indices.exists({ index: 'usuarios' });
        if (!indexExists.body) {
            console.log('Creando índice usuarios...');
            await client.indices.create({
                index: 'usuarios',
                body: {
                    mappings: {
                        properties: {
                            username: { type: 'keyword' },
                            password: { type: 'keyword' },
                            role: { type: 'keyword' },
                            googleId: { type: 'keyword' },
                            email: { type: 'keyword' },
                            createdAt: { type: 'date' },
                            updatedAt: { type: 'date' },
                            passwordLastChanged: { type: 'date' }
                        }
                    }
                }
            });
        }

        // Asegurarse de que el índice de análisis existe
        const analysisIndexExists = await client.indices.exists({ index: 'analisis' });
        if (!analysisIndexExists.body) {
            console.log('Creando índice analisis...');
            await client.indices.create({
                index: 'analisis',
                body: {
                    mappings: {
                        properties: {                            username: { type: 'keyword' },                            timestamp: { type: 'date' },
                            analysis_type: { type: 'keyword' },
                            result: {
                                type: 'object',
                                properties: {
                                    services: { type: 'keyword' },
                                    technologies: { type: 'keyword' },
                                    detected_services: { type: 'keyword' },
                                    scan_details: {
                                        type: 'object',
                                        properties: {
                                            timestamp: { type: 'date' },
                                            duration: { type: 'keyword' },
                                            status: { type: 'keyword' }
                                        }
                                    }
                                }
                            },
                            mitre_correlations: {
                                type: 'nested',
                                properties: {
                                    service: { type: 'keyword' },
                                    techniques: {
                                        type: 'nested',
                                        properties: {
                                            technique_id: { type: 'keyword' },
                                            name: { type: 'text' },
                                            description: { type: 'text' },
                                            tactic: { type: 'keyword' },
                                            references: { type: 'keyword' }
                                        }
                                    }
                                }
                            },
                            status: { type: 'keyword' }
                        }
                    }
                }
            });
        }

        // Sincronizar cada usuario
        for (const user of users) {
            const normalizedUsername = user.username.toLowerCase();
            console.log(`Sincronizando usuario: ${normalizedUsername}`);
            
            // Asegurarse de que todos los campos necesarios existen
            const userToSync = {
                ...user,
                createdAt: user.createdAt || Date.now(),
                updatedAt: user.updatedAt || Date.now(),
                email: user.email || null,
                passwordLastChanged: user.passwordLastChanged || null
            };

            // Usar el username como ID para evitar duplicados
            await client.index({
                index: 'usuarios',
                id: normalizedUsername,
                body: userToSync,
                refresh: true
            });
        }        console.log('Sincronización completada exitosamente');
        
        // Verificar la sincronización
        const { body } = await client.search({
            index: 'usuarios',
            body: {
                query: { match_all: {} },
                size: 1000,
                sort: [
                    { role: "desc" },  // primero admins, luego users
                    { username: "asc" } // alfabéticamente por username
                ]
            }
        });

        console.log(`\nTotal de usuarios en OpenSearch: ${body.hits.total.value}`);
        console.log('\nListado completo de usuarios:');
        console.log('---------------------------');
        
        body.hits.hits.forEach(hit => {
            const user = hit._source;
            console.log(`\nUsername: ${user.username}`);
            console.log(`Role: ${user.role}`);
            console.log(`Auth Type: ${user.googleId ? 'Google Auth' : 'Password Auth'}`);
            console.log(`Email: ${user.email || 'No especificado'}`);
            console.log(`Última actualización: ${new Date(user.updatedAt).toLocaleString()}`);
            console.log('---------------------------');
        });

        // Verificar que todos los usuarios del archivo JSON están en OpenSearch
        const dbUsernames = new Set(body.hits.hits.map(hit => hit._source.username.toLowerCase()));
        const fileUsernames = new Set(users.map(u => u.username.toLowerCase()));

        const missingInDB = [...fileUsernames].filter(u => !dbUsernames.has(u));
        const missingInFile = [...dbUsernames].filter(u => !fileUsernames.has(u));        if (missingInDB.length > 0) {
            console.log('\n⚠️ Usuarios en users.json pero no en OpenSearch:', missingInDB);
        }
        if (missingInFile.length > 0) {
            console.log('\n⚠️ Usuarios en OpenSearch pero no en users.json:', missingInFile);
            console.log('\nEliminando usuarios que no existen en users.json...');
            for (const username of missingInFile) {
                await deleteUser(username);
            }
        }
        if (missingInDB.length === 0 && missingInFile.length === 0) {
            console.log('\n✅ Todos los usuarios están correctamente sincronizados');
        }
        
    } catch (error) {
        console.error('Error durante la sincronización:', error);
    }
}

async function getAnalysisWithCorrelations(username) {
    try {
        const { body } = await client.search({
            index: 'analisis',
            body: {
                query: {
                    bool: {
                        must: [
                            { term: { username: username.toLowerCase() } }
                        ]
                    }
                },
                sort: [
                    { timestamp: "desc" }
                ],
                size: 10
            }
        });

        return body.hits.hits.map(hit => ({
            id: hit._id,
            timestamp: hit._source.timestamp,
            type: hit._source.analysis_type,
            result: hit._source.result,
            status: hit._source.status,
            correlations: hit._source.mitre_correlations
        }));
    } catch (error) {
        console.error(`Error al recuperar análisis para ${username}:`, error.message);
        return [];
    }
}

module.exports = { 
    syncUsers, 
    deleteUser,
    saveAnalysis,
    getAnalysisWithCorrelations
};

// Ejecutar la sincronización solo si este archivo se ejecuta directamente
if (require.main === module) {
    syncUsers().then(() => {
        console.log('Proceso de sincronización finalizado');
        process.exit(0);
    }).catch(error => {
        console.error('Error fatal:', error);
        process.exit(1);
    });
}
