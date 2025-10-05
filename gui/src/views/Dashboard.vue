<template>
  <div class="dashboard">
    <!-- Stats Cards -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-icon">
          <el-icon><User /></el-icon>
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ agentStats.total }}</div>
          <div class="stat-label">Total Agents</div>
        </div>
      </div>

      <div class="stat-card">
        <div class="stat-icon active">
          <el-icon><Connection /></el-icon>
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ agentStats.active }}</div>
          <div class="stat-label">Active Agents</div>
        </div>
      </div>

      <div class="stat-card">
        <div class="stat-icon">
          <el-icon><Monitor /></el-icon>
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ agentStats.windows }}</div>
          <div class="stat-label">Windows</div>
        </div>
      </div>

      <div class="stat-card">
        <div class="stat-icon">
          <el-icon><Platform /></el-icon>
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ agentStats.linux }}</div>
          <div class="stat-label">Linux</div>
        </div>
      </div>
    </div>

    <!-- Main Content Grid -->
    <div class="dashboard-grid">
      <!-- Recent Agents -->
      <div class="dashboard-card">
        <div class="card-header">
          <h3>Recent Agents</h3>
          <el-button @click="$router.push('/agents')" text type="primary">
            View All
          </el-button>
        </div>
        <div class="card-content">
          <div v-if="agentsStore.loading" class="loading-state">
            <el-icon class="is-loading"><Loading /></el-icon>
            <span>Loading agents...</span>
          </div>
          <div v-else-if="recentAgents.length === 0" class="empty-state">
            <el-icon><User /></el-icon>
            <span>No agents connected yet</span>
          </div>
          <div v-else class="agent-list">
            <div
              v-for="agent in recentAgents"
              :key="agent.id"
              class="agent-item"
              @click="selectAgent(agent.id)"
            >
              <div class="agent-info">
                <div class="agent-name">{{ agent.hostname }}</div>
                <div class="agent-details">
                  {{ agent.username }}@{{ agent.domain }} • {{ agent.os }}
                </div>
              </div>
              <div class="agent-status">
                <el-tag
                  :type="getStatusType(agent)"
                  size="small"
                  effect="plain"
                >
                  {{ getAgentStatus(agent) }}
                </el-tag>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Connection Status -->
      <div class="dashboard-card">
        <div class="card-header">
          <h3>Connection Status</h3>
          <el-button
            @click="connectionStore.refreshStatus()"
            :loading="refreshing"
            text
            type="primary"
            size="small"
          >
            Refresh
          </el-button>
        </div>
        <div class="card-content">
          <div class="connection-info">
            <div class="connection-item">
              <span class="label">Server:</span>
              <span class="value">{{ connectionStore.serverUrl }}</span>
            </div>
            <div class="connection-item">
              <span class="label">Status:</span>
              <el-tag
                :type="connectionStore.isConnected ? 'success' : 'danger'"
                size="small"
              >
                {{ connectionStore.status }}
              </el-tag>
            </div>
            <div class="connection-item" v-if="connectionStore.lastConnected">
              <span class="label">Last Connected:</span>
              <span class="value">{{
                formatDate(connectionStore.lastConnected)
              }}</span>
            </div>
            <div class="connection-item">
              <span class="label">Auto-Refresh:</span>
              <el-switch
                v-model="connectionStore.autoRefresh"
                @change="updateAutoRefresh"
                size="small"
              />
            </div>
          </div>
        </div>
      </div>

      <!-- Quick Actions -->
      <div class="dashboard-card">
        <div class="card-header">
          <h3>Quick Actions</h3>
        </div>
        <div class="card-content">
          <div class="action-grid">
            <el-button
              @click="$router.push('/agents')"
              type="primary"
              :icon="User"
              :disabled="!connectionStore.isConnected"
            >
              Manage Agents
            </el-button>
            <el-button
              @click="$router.push('/tasks')"
              type="success"
              :icon="List"
              :disabled="!connectionStore.isConnected"
            >
              View Tasks
            </el-button>
            <el-button
              @click="$router.push('/files')"
              type="warning"
              :icon="Folder"
              :disabled="!connectionStore.isConnected"
            >
              File Manager
            </el-button>
            <el-button
              @click="showConnectionDialog"
              type="info"
              :icon="Setting"
            >
              Connection Settings
            </el-button>
          </div>
        </div>
      </div>

      <!-- System Information -->
      <div class="dashboard-card">
        <div class="card-header">
          <h3>System Information</h3>
        </div>
        <div class="card-content">
          <div class="system-info">
            <div class="info-item">
              <span class="label">GUI Version:</span>
              <span class="value">v1.0.0</span>
            </div>
            <div class="info-item">
              <span class="label">Platform:</span>
              <span class="value">{{ platform }}</span>
            </div>
            <div class="info-item">
              <span class="label">Theme:</span>
              <span class="value">{{ connectionStore.theme }}</span>
            </div>
            <div class="info-item">
              <span class="label">Log Level:</span>
              <span class="value">{{ connectionStore.logLevel }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useConnectionStore } from '@/stores/connection'
import { useAgentsStore } from '@/stores/agents'
import { ElMessage } from 'element-plus'
import dayjs from 'dayjs'

const router = useRouter()
const connectionStore = useConnectionStore()
const agentsStore = useAgentsStore()

const refreshing = ref(false)
const platform = ref('Unknown')
let refreshInterval: NodeJS.Timeout | null = null

// Computed properties
const agentStats = computed(() => agentsStore.agentStats)

const recentAgents = computed(() => {
  return agentsStore.agents
    .slice()
    .sort((a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime())
    .slice(0, 5)
})

// Methods
const selectAgent = (agentId: string) => {
  agentsStore.selectAgent(agentId)
  router.push(`/agents/${agentId}`)
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

const formatDate = (date: Date) => {
  return dayjs(date).format('YYYY-MM-DD HH:mm:ss')
}

const updateAutoRefresh = async (value: boolean) => {
  try {
    await connectionStore.updateSettings({ auto_refresh: value })
    ElMessage.success('Auto-refresh setting updated')
  } catch (error) {
    ElMessage.error('Failed to update setting')
  }
}

const showConnectionDialog = () => {
  // This would emit an event to the parent component to show the connection dialog
  // For now, we'll navigate to settings
  router.push('/settings')
}

const detectPlatform = () => {
  const userAgent = navigator.userAgent
  if (userAgent.includes('Windows')) return 'Windows'
  if (userAgent.includes('Mac')) return 'macOS'
  if (userAgent.includes('Linux')) return 'Linux'
  return 'Unknown'
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
  platform.value = detectPlatform()

  if (connectionStore.isConnected) {
    try {
      await agentsStore.fetchAgents()
      setupAutoRefresh()
    } catch (error) {
      console.error('Failed to fetch agents:', error)
    }
  }
})

onUnmounted(() => {
  clearAutoRefresh()
})

// Watch for connection changes
const unwatchConnection = connectionStore.$subscribe(
  async (mutation, state) => {
    if (state.isConnected) {
      try {
        await agentsStore.fetchAgents()
        setupAutoRefresh()
      } catch (error) {
        console.error('Failed to fetch agents after connection:', error)
      }
    } else {
      clearAutoRefresh()
      agentsStore.agents = []
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
.dashboard {
  padding: 0;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}

.stat-card {
  background: var(--el-bg-color);
  border: 1px solid var(--el-border-color-light);
  border-radius: 8px;
  padding: 20px;
  display: flex;
  align-items: center;
  gap: 16px;
  transition: all 0.3s ease;
}

.stat-card:hover {
  border-color: var(--el-color-primary);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.stat-icon {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  background: var(--el-color-primary-light-9);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 24px;
  color: var(--el-color-primary);
}

.stat-icon.active {
  background: var(--el-color-success-light-9);
  color: var(--el-color-success);
}

.stat-content {
  flex: 1;
}

.stat-value {
  font-size: 28px;
  font-weight: 600;
  color: var(--el-text-color-primary);
  line-height: 1;
}

.stat-label {
  font-size: 14px;
  color: var(--el-text-color-secondary);
  margin-top: 4px;
}

.dashboard-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: 20px;
}

.dashboard-card {
  background: var(--el-bg-color);
  border: 1px solid var(--el-border-color-light);
  border-radius: 8px;
  overflow: hidden;
}

.card-header {
  padding: 16px 20px;
  border-bottom: 1px solid var(--el-border-color-lighter);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-header h3 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
  color: var(--el-text-color-primary);
}

.card-content {
  padding: 20px;
}

.loading-state,
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px 20px;
  color: var(--el-text-color-secondary);
  gap: 12px;
}

.loading-state .el-icon {
  font-size: 24px;
}

.empty-state .el-icon {
  font-size: 48px;
  opacity: 0.5;
}

.agent-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.agent-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.agent-item:hover {
  background: var(--el-fill-color-light);
}

.agent-info {
  flex: 1;
}

.agent-name {
  font-weight: 500;
  color: var(--el-text-color-primary);
  margin-bottom: 4px;
}

.agent-details {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.connection-info,
.system-info {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.connection-item,
.info-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.label {
  font-size: 14px;
  color: var(--el-text-color-secondary);
}

.value {
  font-size: 14px;
  color: var(--el-text-color-primary);
  font-weight: 500;
}

.action-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

@media (max-width: 768px) {
  .stats-grid {
    grid-template-columns: repeat(2, 1fr);
  }

  .dashboard-grid {
    grid-template-columns: 1fr;
  }

  .action-grid {
    grid-template-columns: 1fr;
  }
}
</style>
