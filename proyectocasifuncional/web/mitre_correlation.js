const { Client } = require('@opensearch-project/opensearch');
const OPENSEARCH_HOST = 'http://localhost:9200';
const MITRE_INDEX = 'mitre-attack';

const mitreClient = new Client({ node: OPENSEARCH_HOST });

async function correlateServiceWithMitre(serviceName) {
  // Busca técnicas MITRE ATT&CK relacionadas con el nombre de un servicio 
  const { body } = await mitreClient.search({
    index: MITRE_INDEX,
    body: {
      query: {
        bool: {
          should: [
            { match_phrase: { name: serviceName } },
            { match: { name: serviceName } },
            { wildcard: { name: `*${serviceName.toLowerCase()}*` } }
          ]
        }
      }
    }
  });  return (body.hits.hits || []).map(hit => {
    const source = hit._source;
    return {
      id: source.technique_id || hit._id,
      name: source.name || 'Unknown Technique',
      description: source.description || '',
      tactic: source.tactic || 'unknown',
      references: source.references || []
    };
  });
}

module.exports = { correlateServiceWithMitre };
