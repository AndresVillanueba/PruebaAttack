// Función para mostrar los análisis y sus correlaciones MITRE
async function showAnalysisResults(username) {
    try {
        const response = await fetch(`/api/analysis/${username}`);
        const analyses = await response.json();
        
        let html = '<div class="analysis-results">';
        
        analyses.forEach(analysis => {
            html += `
                <div class="analysis-card mb-4 p-3 border rounded">
                    <h4>Análisis ${analysis.type}</h4>
                    <p class="text-muted">Fecha: ${analysis.timestamp}</p>
                    
                    <div class="result-section">
                        <h5>Resultados:</h5>
                        <pre>${JSON.stringify(analysis.result, null, 2)}</pre>
                    </div>
                    
                    ${analysis.correlations.length > 0 ? `
                        <div class="correlations-section mt-3">
                            <h5>Correlaciones MITRE ATT&CK:</h5>
                            ${analysis.correlations.map(corr => `
                                <div class="service-correlation mb-2">
                                    <h6 class="text-primary">Servicio: ${corr.service}</h6>
                                    <div class="techniques-list">
                                        ${corr.techniques.map(tech => `
                                            <div class="technique-card p-2 mb-2 bg-light">
                                                <strong>${tech.id} - ${tech.name}</strong>
                                                <br>
                                                <span class="badge bg-info">${tech.tactic}</span>
                                                <p class="mt-1 mb-0 small">${tech.description}</p>
                                            </div>
                                        `).join('')}
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    ` : '<p>No se encontraron correlaciones MITRE</p>'}
                </div>
            `;
        });
        
        html += '</div>';
        
        // Asumiendo que tienes un div con id="analysisResults" para mostrar los resultados
        document.getElementById('analysisResults').innerHTML = html;
        
    } catch (error) {
        console.error('Error al obtener los análisis:', error);
        alert('Error al cargar los resultados del análisis');
    }
}

// Añadir esto a tu botón existente
document.getElementById('showAnalysisButton').addEventListener('click', () => {
    const username = getCurrentUsername(); // Función que debes tener para obtener el usuario actual
    showAnalysisResults(username);
});
