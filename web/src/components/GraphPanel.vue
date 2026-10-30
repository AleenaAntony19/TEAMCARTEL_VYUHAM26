<template>
  <div class="graph-panel">
    <div class="panel-header">
      <div class="header-title-group">
        <span class="panel-title mono">GRAPH RELATIONSHIP VISUALIZATION</span>
        <span class="graph-stats mono" v-if="graphData?.nodes">
          ({{ graphData.nodes.length }} nodes, {{ graphData.edges.length }} edges)
        </span>
      </div>
      
      <div class="header-tools">
        <button
          class="tool-btn mono"
          :class="{ active: showDeliberationComm }"
          @click="toggleDeliberationComm"
          title="Highlight Multi-Agent Persona Communication Network"
        >
          <span>⚡ Comm Deliberation</span>
        </button>
        <button class="tool-btn mono" @click="renderGraph" title="Refresh Graph Layout">
          <span class="icon-refresh">↻</span>
          <span>Refresh</span>
        </button>
        <button class="tool-btn mono" @click="$emit('toggle-maximize')" title="Toggle Maximize">
          <span class="icon-maximize">⛶</span>
        </button>
      </div>
    </div>

    <div class="graph-container" ref="graphContainer">
      <!-- D3 Graph Visualization -->
      <div v-show="hasGraphData" class="graph-view">
        <svg ref="graphSvg" class="graph-svg"></svg>

        <!-- Floating Node / Edge Details Card -->
        <div v-if="selectedItem" class="detail-panel">
          <div class="detail-panel-header">
            <span class="detail-title mono">
              {{ selectedItem.type === 'node' ? 'Node Details' : 'Relationship' }}
            </span>
            <span
              v-if="selectedItem.type === 'node'"
              class="detail-type-badge mono"
              :style="{ background: selectedItem.color, color: '#FFFFFF' }"
            >
              {{ selectedItem.entityType }}
            </span>
            <button class="detail-close" @click="closeDetailPanel">×</button>
          </div>

          <!-- Node Details -->
          <div v-if="selectedItem.type === 'node'" class="detail-content">
            <div class="detail-row">
              <span class="detail-label">Name:</span>
              <span class="detail-value font-bold">{{ selectedItem.data.name }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">UUID:</span>
              <span class="detail-value mono uuid-text">{{ selectedItem.data.uuid }}</span>
            </div>
            <div class="detail-row" v-if="selectedItem.data.created_at">
              <span class="detail-label">Created:</span>
              <span class="detail-value">{{ formatDateTime(selectedItem.data.created_at) }}</span>
            </div>

            <!-- Properties -->
            <div class="detail-section" v-if="hasProperties(selectedItem.data.attributes)">
              <div class="section-title">Properties:</div>
              <div class="properties-list">
                <div v-for="(val, key) in selectedItem.data.attributes" :key="key" class="property-item">
                  <span class="property-key mono">{{ key }}:</span>
                  <span class="property-value">{{ val || 'None' }}</span>
                </div>
              </div>
            </div>

            <!-- Summary -->
            <div class="detail-section" v-if="selectedItem.data.summary">
              <div class="section-title">Summary:</div>
              <div class="summary-text">{{ selectedItem.data.summary }}</div>
            </div>

          </div>

          <!-- Edge Details -->
          <div v-else class="detail-content">
            <div class="edge-relation-header mono">
              {{ selectedItem.data.source_name }} → {{ selectedItem.data.name || 'RELATES_TO' }} → {{ selectedItem.data.target_name }}
            </div>

            <div class="detail-row">
              <span class="detail-label">UUID:</span>
              <span class="detail-value mono uuid-text">{{ selectedItem.data.uuid }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Label:</span>
              <span class="detail-value mono">{{ selectedItem.data.name || 'RELATES_TO' }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Type:</span>
              <span class="detail-value mono">{{ selectedItem.data.fact_type || 'REL' }}</span>
            </div>
                        <div class="detail-row">
              <span class="detail-label">Scrape:</span>
              <span class="detail-value mono" :style="{ color: selectedItem.data.kind === 'scrape' ? 'var(--red)' : 'inherit' }">
                {{ selectedItem.data.kind === 'scrape' ? 'ACTIVE (Red dashed)' : 'Standard Relation' }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Empty State -->
      <div v-if="!hasGraphData" class="graph-state">
        <div class="empty-box mono">
          <div class="empty-icon">❖</div>
          <p class="empty-title">AWAITING DATA</p>
          <p class="empty-desc">The graph grows from real findings, agents and scout events.</p>
        </div>
      </div>
    </div>

    <!-- Bottom Left Legend -->
    <div class="graph-legend" v-if="hasGraphData">
      <div class="legend-header mono">NODE TYPES</div>
      <div class="legend-items">
        <div class="legend-item" v-for="type in legendEntities" :key="type.name">
          <span class="legend-dot" :style="{ background: type.color }"></span>
          <span class="legend-label">{{ type.name }}</span>
        </div>
        <!-- Web Scrape Entry -->
        <div class="legend-item scrape-item">
          <span class="legend-swatch-scrape"></span>
          <span class="legend-label scrape-label">Web scrape</span>
        </div>
      </div>
    </div>

    <!-- Edge Labels Toggle -->
    <div class="edge-labels-toggle mono" v-if="hasGraphData">
      <label class="toggle-container">
        <input type="checkbox" v-model="showEdgeLabels" />
        <span class="checkbox-custom"></span>
        <span class="toggle-text">Show Edge Labels</span>
      </label>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import * as d3 from 'd3'
import { ENTITY, getEntityColor } from '../theme/entities'

const props = defineProps({
  graphData: {
    type: Object,
    default: () => ({ nodes: [], edges: [] })
  }
})

defineEmits(['toggle-maximize'])

const graphContainer = ref(null)
const graphSvg = ref(null)
const selectedItem = ref(null)
const showEdgeLabels = ref(true)
const showDeliberationComm = ref(true)

const toggleDeliberationComm = () => {
  showDeliberationComm.value = !showDeliberationComm.value
  renderGraph()
}

let currentSimulation = null
let layout = new Map() // node positions survive redraws, so the graph does not jump on every event
let zoomState = null
let redrawTimer = null
let linkLabelsRef = null
let linkLabelBgRef = null

const hasGraphData = computed(() => {
  return props.graphData && props.graphData.nodes && props.graphData.nodes.length > 0
})

const legendEntities = computed(() => {
  const present = new Set((props.graphData?.nodes || []).map(n => n.type))
  return Object.keys(ENTITY).filter(name => present.has(name)).map(name => ({ name, color: ENTITY[name] }))
})

const formatDateTime = (str) => {
  if (!str) return ''
  try {
    const d = new Date(str)
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      hour12: true
    })
  } catch (e) {
    return str
  }
}

const hasProperties = (attrs) => {
  return attrs && typeof attrs === 'object' && Object.keys(attrs).length > 0
}

const closeDetailPanel = () => {
  selectedItem.value = null
}

const renderGraph = () => {
  if (!graphSvg.value || !graphContainer.value || !hasGraphData.value) return

  if (currentSimulation) {
    currentSimulation.stop()
  }

  const container = graphContainer.value
  const width = container.clientWidth || 600
  const height = container.clientHeight || 500

  const svg = d3.select(graphSvg.value)
    .attr('width', width)
    .attr('height', height)
    .attr('viewBox', `0 0 ${width} ${height}`)

  svg.selectAll('*').remove()

  const rawNodes = props.graphData.nodes || []
  const rawEdges = props.graphData.edges || []

  const nodeMap = {}
  rawNodes.forEach(n => {
    nodeMap[n.uuid] = n
  })

  const nodes = rawNodes.map(n => ({
    id: n.uuid,
    name: n.name || 'Unnamed',
    type: n.type,
    rawData: n,
    ...layout.get(n.uuid)
  }))

  const nodeIds = new Set(nodes.map(n => n.id))

  const edges = rawEdges
    .filter(e => nodeIds.has(e.source_node_uuid) && nodeIds.has(e.target_node_uuid))
    .map((e, idx) => ({
      id: e.uuid || `edge_${idx}`,
      source: e.source_node_uuid,
      target: e.target_node_uuid,
      name: e.name || e.fact_type || 'REL',
      fact_type: e.fact_type || 'REL',
      kind: e.kind || 'rel',
      rawData: {
        ...e,
        source_name: nodeMap[e.source_node_uuid]?.name || 'Unknown',
        target_name: nodeMap[e.target_node_uuid]?.name || 'Unknown'
      }
    }))

  const g = svg.append('g')

  // Zoom & Pan
  const zoom = d3.zoom()
    .extent([[0, 0], [width, height]])
    .scaleExtent([0.15, 4])
    .on('zoom', (event) => {
      g.attr('transform', event.transform)
      zoomState = event.transform
    })
  svg.call(zoom)
  if (zoomState) svg.call(zoom.transform, zoomState)

  // Force simulation
  const simulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(edges).id(d => d.id).distance(110))
    .force('charge', d3.forceManyBody().strength(-280))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collide', d3.forceCollide(32))
    .force('x', d3.forceX(width / 2).strength(0.05))
    .force('y', d3.forceY(height / 2).strength(0.05))

  currentSimulation = simulation

  // Links Group
  const linkGroup = g.append('g').attr('class', 'links')

  const link = linkGroup.selectAll('path')
    .data(edges)
    .enter().append('path')
    .attr('fill', 'none')
    .attr('stroke', d => {
      if (d.kind === 'scrape') return 'var(--red)'
      if (showDeliberationComm.value && (d.name?.includes('DELIBERATES') || d.name?.includes('CROSS_EXAMINES') || d.name?.includes('CHALLENGES') || d.name?.includes('ATTACKS'))) {
        return 'var(--blue)'
      }
      return 'var(--line)'
    })
    .attr('stroke-width', d => {
      if (d.kind === 'scrape') return 1.6
      if (showDeliberationComm.value && (d.name?.includes('DELIBERATES') || d.name?.includes('CROSS_EXAMINES') || d.name?.includes('CHALLENGES') || d.name?.includes('ATTACKS'))) {
        return 1.8
      }
      return 1.2
    })
    .attr('class', d => {
      if (d.kind === 'scrape') return 'scrape-edge'
      if (showDeliberationComm.value && (d.name?.includes('DELIBERATES') || d.name?.includes('CROSS_EXAMINES') || d.name?.includes('CHALLENGES') || d.name?.includes('ATTACKS'))) {
        return 'delib-edge'
      }
      return 'rel-edge'
    })
    .style('cursor', 'pointer')
    .on('click', (event, d) => {
      event.stopPropagation()
      selectedItem.value = {
        type: 'edge',
        data: d.rawData
      }
    })

  // Link Labels BG
  const linkLabelBg = linkGroup.selectAll('rect')
    .data(edges)
    .enter().append('rect')
    .attr('fill', 'var(--panel)')
    .attr('stroke', 'var(--line)')
    .attr('stroke-width', 0.5)
    .style('cursor', 'pointer')
    .style('display', showEdgeLabels.value ? 'block' : 'none')
    .on('click', (event, d) => {
      event.stopPropagation()
      selectedItem.value = {
        type: 'edge',
        data: d.rawData
      }
    })

  // Link Labels Text
  const linkLabels = linkGroup.selectAll('text')
    .data(edges)
    .enter().append('text')
    .text(d => d.name)
    .attr('font-size', '9px')
    .attr('font-family', 'var(--font-mono)')
    .attr('fill', d => (d.kind === 'scrape' ? 'var(--red)' : 'var(--ink)'))
    .attr('text-anchor', 'middle')
    .attr('dominant-baseline', 'middle')
    .style('cursor', 'pointer')
    .style('display', showEdgeLabels.value ? 'block' : 'none')
    .on('click', (event, d) => {
      event.stopPropagation()
      selectedItem.value = {
        type: 'edge',
        data: d.rawData
      }
    })

  linkLabelsRef = linkLabels
  linkLabelBgRef = linkLabelBg

  // Nodes Group
  const nodeGroup = g.append('g').attr('class', 'nodes')

  const node = nodeGroup.selectAll('g')
    .data(nodes)
    .enter().append('g')
    .style('cursor', 'pointer')
    .call(d3.drag()
      .on('start', (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart()
        d.fx = d.x
        d.fy = d.y
      })
      .on('drag', (event, d) => {
        d.fx = event.x
        d.fy = event.y
      })
      .on('end', (event, d) => {
        if (!event.active) simulation.alphaTarget(0)
        d.fx = null
        d.fy = null
      })
    )
    .on('click', (event, d) => {
      event.stopPropagation()
      selectedItem.value = {
        type: 'node',
        data: d.rawData,
        entityType: d.type,
        color: getEntityColor(d.type)
      }
    })

  // Node Shape: Sharp/Hexagonal styled circle with 1.5px hairline border
  node.append('circle')
    .attr('r', 10)
    .attr('fill', d => getEntityColor(d.type))
    .attr('stroke', 'var(--panel)')
    .attr('stroke-width', 2)

  // Node Inner accent
  node.append('circle')
    .attr('r', 3)
    .attr('fill', '#FFFFFF')
    .attr('opacity', 0.8)

  // Node Label
  node.append('text')
    .text(d => (d.name.length > 12 ? d.name.substring(0, 11) + '…' : d.name))
    .attr('font-size', '11px')
    .attr('font-family', 'var(--font-ui)')
    .attr('font-weight', '600')
    .attr('fill', 'var(--ink)')
    .attr('dx', 14)
    .attr('dy', 4)
    .style('pointer-events', 'none')

  // Simulation Tick
  simulation.on('tick', () => {
    link.attr('d', d => {
      return `M${d.source.x},${d.source.y} L${d.target.x},${d.target.y}`
    })

    linkLabels
      .attr('x', d => (d.source.x + d.target.x) / 2)
      .attr('y', d => (d.source.y + d.target.y) / 2)

    linkLabelBg.each(function(d, i) {
      const textEl = linkLabels.nodes()[i]
      if (textEl) {
        const bbox = textEl.getBBox()
        d3.select(this)
          .attr('x', bbox.x - 3)
          .attr('y', bbox.y - 1)
          .attr('width', bbox.width + 6)
          .attr('height', bbox.height + 2)
      }
    })

    node.attr('transform', d => `translate(${d.x},${d.y})`)
    layout = new Map(nodes.map(n => [n.id, { x: n.x, y: n.y }]))
  })
}

watch(() => props.graphData, () => {
  clearTimeout(redrawTimer)
  redrawTimer = setTimeout(renderGraph, 400) // events arrive in bursts
}, { deep: true })

watch(showEdgeLabels, (val) => {
  if (linkLabelsRef) linkLabelsRef.style('display', val ? 'block' : 'none')
  if (linkLabelBgRef) linkLabelBgRef.style('display', val ? 'block' : 'none')
})

onMounted(() => {
  nextTick(() => {
    renderGraph()
  })
  window.addEventListener('resize', renderGraph)
})

onUnmounted(() => {
  clearTimeout(redrawTimer)
  if (currentSimulation) currentSimulation.stop()
  window.removeEventListener('resize', renderGraph)
})
</script>

<style scoped>
.graph-panel {
  width: 100%;
  height: 100%;
  background: var(--fascia);
  display: flex;
  flex-direction: column;
  position: relative;
  overflow: hidden;
}

.panel-header {
  height: 40px;
  background: var(--panel);
  border-bottom: 1px solid var(--line);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 16px;
  flex-shrink: 0;
  z-index: 10;
}

.header-title-group {
  display: flex;
  align-items: center;
  gap: 10px;
}

.panel-title {
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.8px;
  color: var(--ink);
}

.graph-stats {
  font-size: 11px;
  color: var(--blue);
}

.header-tools {
  display: flex;
  align-items: center;
  gap: 6px;
}

.tool-btn {
  background: var(--fascia);
  border: 1px solid var(--line);
  color: var(--ink);
  font-size: 11px;
  font-weight: 600;
  padding: 3px 10px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 5px;
  transition: all 0.15s ease;
}

.tool-btn:hover:not(:disabled) {
  border-color: var(--ink);
  background: var(--panel);
}

.tool-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.icon-refresh.spinning {
  display: inline-block;
  animation: spin 1s infinite linear;
}

@keyframes spin {
  100% { transform: rotate(360deg); }
}

.graph-container {
  flex: 1;
  position: relative;
  overflow: hidden;
}

.graph-view, .graph-svg {
  width: 100%;
  height: 100%;
}

/* Floating Details Panel */
.detail-panel {
  position: absolute;
  top: 14px;
  right: 14px;
  width: 320px;
  max-height: calc(100% - 28px);
  background: var(--panel);
  border: 1px solid var(--ink);
  display: flex;
  flex-direction: column;
  overflow: hidden;
  z-index: 50;
}

.detail-panel-header {
  height: 38px;
  background: var(--fascia);
  border-bottom: 1px solid var(--line);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 12px;
}

.detail-title {
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.5px;
  color: var(--ink);
}

.detail-type-badge {
  font-size: 10px;
  font-weight: 700;
  padding: 2px 8px;
}

.detail-close {
  background: transparent;
  border: none;
  font-size: 18px;
  line-height: 1;
  color: var(--ink);
  cursor: pointer;
  padding: 0 4px;
}

.detail-close:hover {
  color: var(--red);
}

.detail-content {
  padding: 14px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 10px;
  font-size: 12.5px;
}

.detail-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 8px;
}

.detail-label {
  color: #6C727A;
  font-weight: 600;
  font-size: 11.5px;
  min-width: 65px;
}

.detail-value {
  color: var(--ink);
  text-align: right;
  word-break: break-all;
}

.uuid-text {
  font-size: 10px;
  color: var(--blue);
}

.detail-section {
  border-top: 1px solid var(--line);
  padding-top: 8px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.section-title {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  color: #6C727A;
  letter-spacing: 0.5px;
}

.properties-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.property-item {
  display: flex;
  justify-content: space-between;
  font-size: 11.5px;
}

.property-key {
  color: #6C727A;
  font-size: 11px;
}

.summary-text {
  font-size: 12px;
  line-height: 1.4;
  color: var(--ink);
  background: var(--fascia);
  padding: 8px;
  border: 1px solid var(--line);
}

.labels-list {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.label-tag {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 2px 6px;
  font-size: 10px;
  font-weight: 600;
  color: var(--ink);
}

.edge-relation-header {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 8px;
  font-size: 11px;
  font-weight: 700;
  color: var(--ink);
  text-align: center;
}

/* Empty / Loading States */
.graph-state {
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.empty-box, .loading-box {
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 24px 32px;
  text-align: center;
  max-width: 360px;
}

.empty-icon {
  font-size: 28px;
  color: var(--line);
  margin-bottom: 12px;
}

.empty-title {
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 1px;
  color: var(--ink);
  margin-bottom: 6px;
}

.empty-desc {
  font-size: 12px;
  color: #6C727A;
  line-height: 1.4;
}

.loading-box {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.5px;
}

.spinner-icon {
  font-size: 18px;
  display: inline-block;
  animation: spin 1s infinite linear;
}

/* Legend - Bottom Left */
.graph-legend {
  position: absolute;
  bottom: 14px;
  left: 14px;
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 10px 14px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  z-index: 20;
  max-width: 280px;
}

.legend-header {
  font-size: 10px;
  font-weight: 800;
  letter-spacing: 1px;
  color: var(--ink);
}

.legend-items {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 5px 12px;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 6px;
}

.legend-dot {
  width: 8px;
  height: 8px;
  flex-shrink: 0;
}

.legend-label {
  font-size: 11px;
  font-weight: 500;
  color: var(--ink);
  white-space: nowrap;
}

.legend-swatch-scrape {
  width: 14px;
  height: 2px;
  background: var(--red);
  border-top: 1px dashed var(--red);
  flex-shrink: 0;
}

.scrape-item {
  grid-column: span 2;
  margin-top: 2px;
  padding-top: 4px;
  border-top: 1px dashed var(--line);
}

.scrape-label {
  color: var(--red);
  font-weight: 700;
}

/* Toggle Switch */
.edge-labels-toggle {
  position: absolute;
  bottom: 14px;
  right: 14px;
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 6px 10px;
  font-size: 10px;
  z-index: 20;
}

.toggle-container {
  display: flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  user-select: none;
}

.toggle-container input {
  cursor: pointer;
}

.delib-edge {
  stroke: var(--blue) !important;
  stroke-dasharray: 4 3 !important;
  animation: delibPulse 1.8s ease-in-out infinite alternate;
}

@keyframes delibPulse {
  0% { stroke-opacity: 0.45; stroke-width: 1.4px; }
  100% { stroke-opacity: 1; stroke-width: 2.2px; }
}

.tool-btn.active {
  background: var(--blue);
  color: #FFFFFF;
  border-color: var(--blue);
}
</style>
