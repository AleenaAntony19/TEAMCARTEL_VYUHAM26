// Graph node classes: only what the backend really produces.
export const ENTITY = {
  Document: '#004E89',
  'Sensitive data': '#E0245E',
  Agent: '#E9724C',
  'MCP tool': '#6B6E70',
  Site: '#1A936F',
  Match: '#C8312B',
  Person: '#4A6178'
}

export const getEntityColor = (type) => ENTITY[type] || ENTITY.Document
