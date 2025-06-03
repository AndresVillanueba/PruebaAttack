const { Client } = require('@opensearch-project/opensearch');
const OPENSEARCH_HOST = 'http://localhost:9200';
const MITRE_INDEX = 'mitre-attack';

const mitreClient = new Client({ node: OPENSEARCH_HOST });

async function correlateServiceWithMitre(serviceName) {
  // Busca técnicas MITRE ATT&CK relacionadas con el nombre de un servicio (case-insensitive, exact y parcial)
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
  });
  return (body.hits.hits || []).map(hit => ({
    technique_id: hit._source.technique_id,
    name: hit._source.name,
    description: hit._source.description,
    tactic: hit._source.tactic,
    references: hit._source.references
  }));
}

module.exports = { correlateServiceWithMitre };
