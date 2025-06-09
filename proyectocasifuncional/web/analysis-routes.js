const express = require('express');
const router = express.Router();
const { getAnalysisWithCorrelations } = require('./sync-users');

// Ruta para obtener los análisis de un usuario
router.get('/api/analysis/:username', async (req, res) => {
    try {
        const username = req.params.username;
        const analyses = await getAnalysisWithCorrelations(username);
        res.json(analyses);
    } catch (error) {
        console.error('Error al obtener análisis:', error);
        res.status(500).json({ error: 'Error al obtener análisis' });
    }
});

module.exports = router;
