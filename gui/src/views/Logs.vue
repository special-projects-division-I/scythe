<template>
  <div class="logs-view">
    <!-- Header -->
    <div class="view-header">
      <div class="header-content">
        <h2>Activity Logs</h2>
        <div class="header-actions">
          <el-button @click="refreshLogs" :loading="loading" type="primary">
            <el-icon><Refresh /></el-icon>
            Refresh
          </el-button>
          <el-button @click="clearLogs" type="danger">
            <el-icon><Delete /></el-icon>
            Clear Logs
          </el-button>
          <el-button @click="exportLogs" type="success">
            <el-icon><Download /></el-icon>
            Export
          </el-button>
        </div>
      </div>
    </div>

    <!-- Filters -->
    <div class="filters-bar">
      <el-select v-model="levelFilter" placeholder="Log Level" clearable style="width: 120px">
        <el-option label="Debug" value="debug" />
        <el-option label="Info" value="info" />
        <el-option label="Warning" value="warning" />
        <el-option label="Error" value="error" />
        <el-option label="Critical" value="critical" />
      </el-select>

      <el-select v-model="sourceFilter" placeholder="Source" clearable style="width: 150px">
        <el-option label="Server" value="server" />
        <el-option label="Agent" value="agent" />
        <el-option label="Task" value="task" />
        <el-option label="File" value="file" />
        <el-option label="System" value="system" />
      </el-select>

      <el-date-picker
        v-model="dateRange"
        type="datetimerange"
        range-separator="To"
        start-placeholder="Start date"
        end-placeholder="End date"
        style="width: 350px"
        @change="onDateRangeChange"
      />

      <el-input
        v-model="searchQuery"
        placeholder="Search logs..."
        :prefix-icon="Search"
        clearable
        style="width: 300px"
      />
    </div>

    <!-- Stats Bar -->
    <div class="stats-bar">
      <div class="stat-item">
        <span class="stat-label">Total:</span>
        <span class="stat-value">{{ filteredLogs.length }}</span>
      </div>
      <div class="stat-item">
        <span class="stat-label">Errors:</span>
        <span class="stat-value error">{{ errorCount }}</span>
      </div>
      <div class="stat-item">
        <span class="stat-label">Warnings:</span>
        <span class="stat-value warning">{{ warningCount }}</span>
      </div>
      <div class="stat-item">
        <span class="stat-label">Last Hour:</span>
        <span class="stat-value">{{ recentCount }}</span>
      </div>
    </div>

    <!-- Logs Table -->
    <div class="logs-container">
      <div v-if="loading" class="loading-state">
        <el-icon class="is-loading"><Loading /></el-icon>
        <span>Loading logs...</span>
      </div>

      <div v-else-if="filteredLogs.length === 0" class="empty-state">
        <el-icon><Document /></el-icon>
        <h3>No logs found</h3>
        <p>{{ searchQuery || levelFilter || sourceFilter ? 'Try adjusting your filters' : 'No activity logged yet' }}</p>
      </div>

      <div v-else class="logs-table">
        <el-table
          :data="paginatedLogs"
          stripe
          height="100%"
          @row-click="selectLog"
        >
          <el-table-column prop="timestamp" label="Time" width="180" sortable>
            <template #default="{ row }">
              {{ formatDate(row.timestamp) }}
            </template>
          </el-table-column>

          <el-table-column prop="level" label="Level" width="100" sortable>
            <template #default="{ row }">
              <el-tag :type="getLevelType(row.level)" size="small">
                {{ row.level.toUpperCase() }}
              </el-tag>
            </template>
          </el-table-column>

          <el-table-column prop="source" label="Source" width="120" sortable>
            <template #default="{ row }">
              <el-tag :type="getSourceType(row.source)" size="small" effect="plain">
                {{ row.source }}
              </el-tag>
            </template>
          </el-table-column>

          <el-table-column prop="agent_id" label="Agent" width="150" sortable>
            <template #default="{ row }">
              <span v-if="row.agent_id">{{ getAgentHostname(row.agent_id) }}</span>
              <span v-else class="text-muted">System</span>
            </template>
          </el-table-column>

          <el-table-column prop="message" label="Message" min-width="300">
            <template #default="{ row }">
              <div class="log-message">
                {{ row.message }}
                <div v-if="row.details" class="log-details">
                  {{ row.details }}
                </div>
              </div>
            </template>
          </el-table-column>

          <el-table-column label="Actions" width="80">
            <template #default="{ row }">
              <el-dropdown @command="(cmd) => handleLogAction(cmd, row)" trigger="click">
                <el-button size="small" text>
                  <el-icon><MoreFilled /></el-icon>
                </el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="view">View Details</el-dropdown-item>
                    <el-dropdown-item command="copy">Copy Message</el-dropdown-item>
                    <el-dropdown-item divided command="delete">Delete</el-dropdown-item>
                  </el-dropdown-menu>
                  </template>
              </el-dropdown>
            </template>
          </el-table-column>
        </el-table>

        <!-- Pagination -->
        <div class="pagination">
          <el-pagination
            v-model:current-page="currentPage"
            v-model:page-size="pageSize"
            :page-sizes="[20, 50, 100, 200]"
            :total="filteredLogs.length"
            layout="total, sizes, prev, pager, next, jumper"
            @size-change="onPageSizeChange"
          />
        </div>
      </div>
    </div>

    <!-- Log Details Dialog -->
    <el-dialog
      v-model="detailsDialogVisible"
      title="Log Details"
      width="800px"
    >
      <div v-if="selectedLog" class="log-details-content">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="Timestamp">{{ formatDate(selectedLog.timestamp) }}</el-descriptions-item>
          <el-descriptions-item label="Level">
            <el-tag :type="getLevelType(selectedLog.level)">{{ selectedLog.level.toUpperCase() }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Source">
            <el-tag :type="getSourceType(selectedLog.source)" effect="plain">{{ selectedLog.source }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Agent ID">{{ selectedLog.agent_id || 'N/A' }}</el-descriptions-item>
          <el-descriptions-item label="Message" :span="2">{{ selectedLog.message }}</el-descriptions-item>
          <el-descriptions-item v-if="selectedLog.details" label="Details" :span="2">
            <pre>{{ selectedLog.details }}</pre>
          </el-descriptions-item>
          <el-descriptions-item v-if="selectedLog.stack_trace" label="Stack Trace" :span="2">
            <pre class="stack-trace">{{ selectedLog.stack_trace }}</pre>
          </el-descriptions-item>
        </el-descriptions>
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useAgentsStore } from '@/stores/agents'
import { ElMessage, ElMessageBox } from 'element-plus'
import dayjs from 'dayjs'

const agentsStore = useAgentsStore()

const logs = ref<any[]>([])
const loading = ref(false)
const levelFilter = ref('')
const sourceFilter = ref('')
const searchQuery = ref('')
const dateRange = ref<[Date, Date] | null>(null)
const currentPage = ref(1)
const pageSize = ref(50)
const detailsDialogVisible = ref(false)
const selectedLog = ref<any>(null)

let refreshInterval: NodeJS.Timeout | null = null

// Sample log data - in real implementation, this would come from the server
const generateSampleLogs = () => {
  const levels = ['info', 'warning', 'error', 'debug', 'critical']
  const sources = ['server', 'agent', 'task', 'file', 'system']
  const messages = [
    'Agent connected successfully',
    'Task completed successfully',
    'Failed to execute command',
    'File uploaded successfully',
    'Connection timeout',
    'Agent disconnected',
    'New task created',
    'File download failed',
    'System startup complete',
    'Authentication successful'
  ]

  const sampleLogs = []
  const now = new Date()

  for (let i = 0; i < 200; i++) {
    const timestamp = new Date(now.getTime() - (i * 5 * 60 * 1000)) // Every 5 minutes
    const level = levels[Math.floor(Math.random() * levels.length)]
    const source = sources[Math.floor(Math.random() * sources.length)]
    const message = messages[Math.floor(Math.random() * messages.length)]

    sampleLogs.push({
      id: `log-${i}`,
      timestamp: timestamp.toISOString(),
      level,
      source,
      agent_id: Math.random() > 0.5 ? `agent-${Math.floor(Math.random() * 5) + 1}` : null,
      message,
      details: Math.random() > 0.7 ? `Additional details for log entry ${i}` : null,
      stack_trace: level === 'error' || level === 'critical' ? `Stack trace for error ${i}` : null
    })
  }

  return sampleLogs
}

// Computed properties
const filteredLogs = computed(() => {
  let filtered = logs.value

  if (levelFilter.value) {
    filtered = filtered.filter(log => log.level === levelFilter.value)
  }

  if (sourceFilter.value) {
    filtered = filtered.filter(log => log.source === sourceFilter.value)
  }

  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    filtered = filtered.filter(log =>
      log.message.toLowerCase().includes(query) ||
      log.details?.toLowerCase().includes(query)
    )
  }

  if (dateRange.value) {
    const [start, end] = dateRange.value
    filtered = filtered.filter(log => {
      const logDate = new Date(log.timestamp)
      return logDate >= start && logDate <= end
    })
  }

  return filtered.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
})

const paginatedLogs = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  const end = start + pageSize.value
  return filteredLogs.value.slice(start, end)
})

const errorCount = computed(() => {
  return filteredLogs.value.filter(log => log.level === 'error' || log.level === 'critical').length
})

const warningCount = computed(() => {
  return filteredLogs.value.filter(log => log.level === 'warning').length
})

const recentCount = computed(() => {
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000)
  return filteredLogs.value.filter(log => new Date(log.timestamp) >= oneHourAgo).length
})

// Methods
const refreshLogs = async () => {
  try {
    loading.value = true

    // In real implementation, fetch logs from server
    // For now, generate sample data
    await new Promise(resolve => setTimeout(resolve, 1000))
    logs.value = generateSampleLogs()

    ElMessage.success('Logs refreshed')
  } catch (error) {
    ElMessage.error('Failed to refresh logs')
  } finally {
    loading.value = false
  }
}

const clearLogs = async () => {
  try {
    await ElMessageBox.confirm(
      'Are you sure you want to clear all logs? This action cannot be undone.',
      'Clear Logs',
      {
        confirmButtonText: 'Clear',
        cancelButtonText: 'Cancel',
        type: 'warning',
      }
    )

    logs.value = []
    ElMessage.success('Logs cleared')
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to clear logs')
    }
  }
}

const exportLogs = () => {
  try {
    const logText = filteredLogs.value.map(log =>
      `${formatDate(log.timestamp)} [${log.level.toUpperCase()}] ${log.source}: ${log.message}${log.details ? '\n' + log.details : ''}`
    ).join('\n\n')

    const blob = new Blob([logText], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `scythe-logs-${dayjs().format('YYYY-MM-DD-HH-mm-ss')}.txt`
    a.click()
    URL.revokeObjectURL(url)

    ElMessage.success('Logs exported successfully')
  } catch (error) {
    ElMessage.error('Failed to export logs')
  }
}

const selectLog = (log: any) => {
  selectedLog.value = log
  detailsDialogVisible.value = true
}

const handleLogAction = async (command: string, log: any) => {
  try {
    switch (command) {
      case 'view':
        selectedLog.value = log
        detailsDialogVisible.value = true
        break
      case 'copy':
        await navigator.clipboard.writeText(log.message)
        ElMessage.success('Message copied to clipboard')
        break
      case 'delete':
        await ElMessageBox.confirm(
          'Are you sure you want to delete this log entry?',
          'Delete Log',
          {
            confirmButtonText: 'Delete',
            cancelButtonText: 'Cancel',
            type: 'warning',
          }
        )
        const index = logs.value.findIndex(l => l.id === log.id)
        if (index !== -1) {
          logs.value.splice(index, 1)
          ElMessage.success('Log deleted')
        }
        break
    }
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error(`Failed to ${command} log: ${error}`)
    }
  }
}

const onDateRangeChange = () => {
  currentPage.value = 1
}

const onPageSizeChange = () => {
  currentPage.value = 1
}

const getLevelType = (level: string) => {
  switch (level) {
    case 'debug': return 'info'
    case 'info': return 'success'
    case 'warning': return 'warning'
    case 'error': return 'danger'
    case 'critical': return 'danger'
    default: return 'info'
  }
}

const getSourceType = (source: string) => {
  switch (source) {
    case 'server': return 'primary'
    case 'agent': return 'success'
    case 'task': return 'warning'
    case 'file': return 'info'
    case 'system': return ''
    default: return 'info'
  }
}

const getAgentHostname = (agentId: string) => {
  const agent = agentsStore.agents.find(a => a.id === agentId)
  return agent ? agent.hostname : agentId
}

const formatDate = (dateString: string) => {
  return dayjs(dateString).format('YYYY-MM-DD HH:mm:ss')
}

const setupAutoRefresh = () => {
  refreshInterval = setInterval(async () => {
    try {
      await refreshLogs()
    } catch (error) {
      // Silent fail for auto-refresh
    }
  }, 60000) // Refresh every minute
}

const clearAutoRefresh = () => {
  if (refreshInterval) {
    clearInterval(refreshInterval)
    refreshInterval = null
  }
}

// Lifecycle
onMounted(async () => {
  await refreshLogs()
  setupAutoRefresh()
})

onUnmounted(() => {
  clearAutoRefresh()
})
</script>

<style scoped>
.logs-view {
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

.filters-bar {
  display: flex;
  gap: 12px;
  margin-bottom: 20px;
  flex-wrap: wrap;
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

.stat-value.error {
  color: var(--el-color-danger);
}

.stat-value.warning {
  color: var(--el-color-warning);
}

.logs-container {
  flex: 1;
  overflow: hidden;
  display: flex;
  flex-direction: column;
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

.logs-table {
  flex: 1;
  display: flex;
  flex-direction: column;
}

.log-message {
  line-height: 1.4;
}

.log-details {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-top: 4px;
}

.pagination {
  padding: 16px 0;
  display: flex;
  justify-content: center;
}

.log-details-content {
  max-height: 60vh;
  overflow-y: auto;
}

.log-details-content pre {
  background: var(--el-fill-color-light);
  padding: 12px;
  border-radius: 4px;
  font-size: 12px;
  line-height: 1.4;
  white-space: pre-wrap;
  word-wrap: break-word;
  margin: 0;
}

.stack-trace {
  color: var(--el-color-danger);
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
}

.text-muted {
  color: var(--el-text-color-placeholder);
  font-style: italic;
}

@media (max-width: 768px) {
  .header-content {
    flex-direction: column;
    gap: 12px;
    align-items: stretch;
  }

  .filters-bar {
    flex-direction: column;
  }

  .filters-bar .el-select,
  .filters-bar .el-date-picker,
  .filters-bar .el-input {
    width: 100% !important;
  }

  .stats-bar {
    flex-wrap: wrap;
    gap: 16px;
  }

  .pagination {
    padding: 12px 0;
  }
}
</style>
