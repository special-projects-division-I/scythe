<template>
  <div class="agents-view">
    <!-- Header -->
    <div class="view-header">
      <div class="header-content">
        <h2>Agents</h2>
        <div class="header-actions">
          <el-button @click="refreshAgents" :loading="agentsStore.loading" type="primary">
            <el-icon><Refresh /></el-icon>
            Refresh
          </el-button>
        </div>
      </div>
    </div>

    <!-- Stats Bar -->
    <div class="stats-bar">
      <div class="stat-item">
        <span class="stat-label">Total:</span>
        <span class="stat-value">{{ agentStats.total }}</span>
      </div>
      <div class="stat-item">
        <span class="stat-label">Active:</span>
        <span class="stat-value active">{{ agentStats.active }}</span>
      </div>
      <div class="stat-item">
        <span class="stat-label">Windows:</span>
        <span class="stat-value">{{ agentStats.windows }}</span>
      </div>
      <div class="stat-item">
        <span class="stat-label">Linux:</span>
        <span class="stat-value">{{ agentStats.linux }}</span>
      </div>
    </div>

    <!-- Filters -->
    <div class="filters-bar">
      <el-input
        v-model="searchQuery"
        placeholder="Search agents..."
        :prefix-icon="Search"
        clearable
        style="width: 300px"
      />
      <el-select v-model="statusFilter" placeholder="Status" clearable style="width: 150px">
        <el-option label="Active" value="active" />
        <el-option label="Idle" value="idle" />
        <el-option label="Stale" value="stale" />
        <el-option label="Inactive" value="inactive" />
      </el-select>
      <el-select v-model="osFilter" placeholder="OS" clearable style="width: 150px">
        <el-option label="Windows" value="windows" />
        <el-option label="Linux" value="linux" />
        <el-option label="macOS" value="mac" />
      </el-select>
    </div>

    <!-- Agents Grid -->
    <div class="agents-container">
      <div v-if="agentsStore.loading" class="loading-state">
        <el-icon class="is-loading"><Loading /></el-icon>
        <span>Loading agents...</span>
      </div>

      <div v-else-if="filteredAgents.length === 0" class="empty-state">
        <el-icon><User /></el-icon>
        <h3>No agents found</h3>
        <p>{{ searchQuery || statusFilter || osFilter ? 'Try adjusting your filters' : 'No agents have connected yet' }}</p>
      </div>

      <div v-else class="agents-grid">
        <div
          v-for="agent in filteredAgents"
          :key="agent.id"
          class="agent-card"
          :class="{ selected: selectedAgentId === agent.id }"
          @click="selectAgent(agent.id)"
        >
          <div class="agent-header">
            <div class="agent-title">
              <h3>{{ agent.hostname }}</h3>
              <el-tag
                :type="getStatusType(agent)"
                size="small"
                effect="plain"
              >
                {{ getAgentStatus(agent) }}
              </el-tag>
            </div>
            <div class="agent-os">
              <el-icon v-if="agent.os.toLowerCase().includes('windows')"><Monitor /></el-icon>
              <el-icon v-else-if="agent.os.toLowerCase().includes('linux')"><Platform /></el-icon>
              <el-icon v-else><Monitor /></el-icon>
              {{ getOSShort(agent.os) }}
            </div>
          </div>

          <div class="agent-info">
            <div class="info-row">
              <span class="label">User:</span>
              <span class="value">{{ agent.username }}@{{ agent.domain }}</span>
            </div>
            <div class="info-row">
              <span class="label">Process:</span>
              <span class="value">{{ agent.process_name }} ({{ agent.process_id }})</span>
            </div>
            <div class="info-row">
              <span class="label">IP:</span>
              <span class="value">{{ agent.internal_ip || agent.remote_ip }}</span>
            </div>
            <div class="info-row">
              <span class="label">Last Seen:</span>
              <span class="value">{{ formatDate(agent.last_seen) }}</span>
            </div>
            <div class="info-row">
              <span class="label">Uptime:</span>
              <span class="value">{{ getAgentUptime(agent) }}</span>
            </div>
          </div>

          <div class="agent-actions">
            <el-button @click.stop="viewAgent(agent.id)" type="primary" size="small">
              <el-icon><View /></el-icon>
              Details
            </el-button>
            <el-button @click.stop="interactAgent(agent.id)" type="success" size="small">
              <el-icon><ChatDotRound /></el-icon>
              Interact
            </el-button>
            <el-dropdown @command="(cmd) => handleAgentAction(cmd, agent.id)" trigger="click">
              <el-button @click.stop size="small" text>
                <el-icon><MoreFilled /></el-icon>
              </el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item command="refresh">Refresh</el-dropdown-item>
                  <el-dropdown-item command="sleep">Configure Sleep</el-dropdown-item>
                  <el-dropdown-item command="screenshot">Screenshot</el-dropdown-item>
                  <el-dropdown-item command="system-info">System Info</el-dropdown-item>
                  <el-dropdown-item divided command="delete" class="danger">Remove Agent</el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </div>
        </div>
      </div>
    </div>

    <!-- Agent Details Dialog -->
    <el-dialog
      v-model="detailsDialogVisible"
      :title="`Agent Details - ${selectedAgent?.hostname}`"
      width="800px"
    >
      <div v-if="selectedAgent" class="agent-details">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="Agent ID">{{ selectedAgent.id }}</el-descriptions-item>
          <el-descriptions-item label="Status">
            <el-tag :type="getStatusType(selectedAgent)">{{ getAgentStatus(selectedAgent) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Hostname">{{ selectedAgent.hostname }}</el-descriptions-item>
          <el-descriptions-item label="Username">{{ selectedAgent.username }}</el-descriptions-item>
          <el-descriptions-item label="Domain">{{ selectedAgent.domain }}</el-descriptions-item>
          <el-descriptions-item label="OS">{{ selectedAgent.os }}</el-descriptions-item>
          <el-descriptions-item label="Architecture">{{ selectedAgent.arch }}</el-descriptions-item>
          <el-descriptions-item label="Process">{{ selectedAgent.process_name }} ({{ selectedAgent.process_id }})</el-descriptions-item>
          <el-descriptions-item label="Integrity Level">{{ selectedAgent.integrity_level }}</el-descriptions-item>
          <el-descriptions-item label="Remote IP">{{ selectedAgent.remote_ip }}</el-descriptions-item>
          <el-descriptions-item label="Internal IP">{{ selectedAgent.internal_ip }}</el-descriptions-item>
          <el-descriptions-item label="Sleep Interval">{{ selectedAgent.sleep_interval }}s</el-descriptions-item>
          <el-descriptions-item label="Jitter">{{ (selectedAgent.jitter * 100).toFixed(0) }}%</el-descriptions-item>
          <el-descriptions-item label="First Seen">{{ formatDate(selectedAgent.first_seen) }}</el-descriptions-item>
          <el-descriptions-item label="Last Seen">{{ formatDate(selectedAgent.last_seen) }}</el-descriptions-item>
        </el-descriptions>
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAgentsStore } from '@/stores/agents'
import { useConnectionStore } from '@/stores/connection'
import { ElMessage, ElMessageBox } from 'element-plus'
import dayjs from 'dayjs'

const router = useRouter()
const agentsStore = useAgentsStore()
const connectionStore = useConnectionStore()

const searchQuery = ref('')
const statusFilter = ref('')
const osFilter = ref('')
const detailsDialogVisible = ref(false)
let refreshInterval: NodeJS.Timeout | null = null

// Computed properties
const agentStats = computed(() => agentsStore.agentStats)
const selectedAgentId = computed(() => agentsStore.selectedAgentId)
const selectedAgent = computed(() => agentsStore.selectedAgent)

const filteredAgents = computed(() => {
  let agents = agentsStore.agents

  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    agents = agents.filter(agent =>
      agent.hostname.toLowerCase().includes(query) ||
      agent.username.toLowerCase().includes(query) ||
      agent.domain.toLowerCase().includes(query) ||
      agent.os.toLowerCase().includes(query) ||
      agent.internal_ip?.includes(query) ||
      agent.remote_ip.includes(query)
    )
  }

  if (statusFilter.value) {
    agents = agents.filter(agent => {
      const status = getAgentStatus(agent).toLowerCase()
      return status === statusFilter.value
    })
  }

  if (osFilter.value) {
    agents = agents.filter(agent =>
      agent.os.toLowerCase().includes(osFilter.value)
    )
  }

  return agents
})

// Methods
const refreshAgents = async () => {
  try {
    await agentsStore.fetchAgents()
    ElMessage.success('Agents refreshed')
  } catch (error) {
    ElMessage.error('Failed to refresh agents')
  }
}

const selectAgent = (agentId: string) => {
  agentsStore.selectAgent(agentId)
}

const viewAgent = (agentId: string) => {
  agentsStore.selectAgent(agentId)
  detailsDialogVisible.value = true
}

const interactAgent = (agentId: string) => {
  router.push(`/agents/${agentId}`)
}

const handleAgentAction = async (command: string, agentId: string) => {
  try {
    switch (command) {
      case 'refresh':
        await agentsStore.refreshAgent(agentId)
        ElMessage.success('Agent refreshed')
        break
      case 'sleep':
        // TODO: Show sleep configuration dialog
        ElMessage.info('Sleep configuration coming soon')
        break
      case 'screenshot':
        await agentsStore.createTask(agentId, 'screenshot', [], 'Screenshot')
        ElMessage.success('Screenshot task created')
        break
      case 'system-info':
        await agentsStore.createTask(agentId, 'systeminfo', [], 'SystemInfo')
        ElMessage.success('System info task created')
        break
      case 'delete':
        await ElMessageBox.confirm(
          'Are you sure you want to remove this agent? This action cannot be undone.',
          'Remove Agent',
          {
            confirmButtonText: 'Remove',
            cancelButtonText: 'Cancel',
            type: 'warning',
          }
        )
        await agentsStore.deleteAgent(agentId)
        ElMessage.success('Agent removed')
        break
    }
  } catch (error) {
    ElMessage.error(`Failed to ${command}: ${error}`)
  }
}

const getAgentStatus = (agent: any) => {
  return agentsStore.getAgentStatus(agent)
}

const getStatusType = (agent: any) => {
  const status = getAgentStatus(agent)
  switch (status) {
    case 'Active': return 'success'
    case 'Idle': return 'warning'
    case 'Stale': return 'danger'
    default: return 'info'
  }
}

const getOSShort = (os: string) => {
  if (os.toLowerCase().includes('windows')) return 'Windows'
  if (os.toLowerCase().includes('linux')) return 'Linux'
  if (os.toLowerCase().includes('mac')) return 'macOS'
  return os.split(' ')[0]
}

const formatDate = (dateString: string) => {
  return dayjs(dateString).format('YYYY-MM-DD HH:mm:ss')
}

const getAgentUptime = (agent: any) => {
  return agentsStore.getAgentUptime(agent)
}

const setupAutoRefresh = () => {
  if (connectionStore.autoRefresh && connectionStore.isConnected) {
    refreshInterval = setInterval(async () => {
      try {
        await agentsStore.fetchAgents()
      } catch (error) {
        // Silent fail for auto-refresh
      }
    }, connectionStore.refreshInterval * 1000)
  }
}

const clearAutoRefresh = () => {
  if (refreshInterval) {
    clearInterval(refreshInterval)
    refreshInterval = null
  }
}

// Lifecycle
onMounted(async () => {
  if (connectionStore.isConnected) {
    await refreshAgents()
    setupAutoRefresh()
  }
})

onUnmounted(() => {
  clearAutoRefresh()
})

// Watch for connection changes
const unwatchConnection = connectionStore.$subscribe(
  async (mutation, state) => {
    if (state.isConnected) {
      await refreshAgents()
      setupAutoRefresh()
    } else {
      clearAutoRefresh()
    }
  }
)

// Watch for auto-refresh changes
const unwatchAutoRefresh = connectionStore.$subscribe(
  (mutation, state) => {
    clearAutoRefresh()
    if (state.auto_refresh && state.isConnected) {
      setupAutoRefresh()
    }
  }
)
</script>

<style scoped>
.agents-view {
  display: flex;
  flex-direction: column;
  height: 100%;
}

.view-header {
  margin-bottom: 20px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-content h2 {
  margin: 0;
  color: var(--el-text-color-primary);
}

.stats-bar {
  display: flex;
  gap: 30px;
  padding: 16px 20px;
  background: var(--el-bg-color);
  border: 1px solid var(--el-border-color-light);
  border-radius: 8px;
  margin-bottom: 20px;
}

.stat-item {
  display: flex;
  align-items: center;
  gap: 8px;
}

.stat-label {
  color: var(--el-text-color-secondary);
  font-size: 14px;
}

.stat-value {
  color: var(--el-text-color-primary);
  font-weight: 600;
  font-size: 16px;
}

.stat-value.active {
  color: var(--el-color-success);
}

.filters-bar {
  display: flex;
  gap: 12px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}

.agents-container {
  flex: 1;
  overflow-y: auto;
}

.loading-state,
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 20px;
  color: var(--el-text-color-secondary);
}

.loading-state .el-icon {
  font-size: 32px;
  margin-bottom: 16px;
}

.empty-state .el-icon {
  font-size: 64px;
  margin-bottom: 16px;
  opacity: 0.5;
}

.empty-state h3 {
  margin: 0 0 8px 0;
  color: var(--el-text-color-primary);
}

.empty-state p {
  margin: 0;
  color: var(--el-text-color-secondary);
}

.agents-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
  gap: 20px;
}

.agent-card {
  background: var(--el-bg-color);
  border: 1px solid var(--el-border-color-light);
  border-radius: 8px;
  padding: 20px;
  cursor: pointer;
  transition: all 0.3s ease;
}

.agent-card:hover {
  border-color: var(--el-color-primary);
  box-shadow: 0 4px 12px rgba(64, 158, 255, 0.15);
  transform: translateY(-2px);
}

.agent-card.selected {
  border-color: var(--el-color-primary);
  background: var(--el-color-primary-light-9);
}

.agent-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 16px;
}

.agent-title h3 {
  margin: 0 0 8px 0;
  color: var(--el-text-color-primary);
  font-size: 18px;
}

.agent-os {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--el-text-color-secondary);
  font-size: 14px;
}

.agent-info {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-bottom: 16px;
}

.info-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.info-row .label {
  color: var(--el-text-color-secondary);
  font-size: 13px;
}

.info-row .value {
  color: var(--el-text-color-primary);
  font-size: 13px;
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
}

.agent-actions {
  display: flex;
  gap: 8px;
  justify-content: flex-end;
}

.agent-details {
  max-height: 500px;
  overflow-y: auto;
}

.danger {
  color: var(--el-color-danger);
}

@media (max-width: 768px) {
  .stats-bar {
    flex-wrap: wrap;
    gap: 16px;
  }

  .filters-bar {
    flex-direction: column;
  }

  .filters-bar .el-input,
  .filters-bar .el-select {
    width: 100% !important;
  }

  .agents-grid {
    grid-template-columns: 1fr;
  }

  .agent-actions {
    flex-wrap: wrap;
  }
}
</style>
