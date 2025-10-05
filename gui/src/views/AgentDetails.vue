<template>
  <div class="agent-details">
    <!-- Header -->
    <div class="view-header">
      <div class="header-content">
        <div class="agent-title">
          <el-button @click="$router.back()" text type="primary">
            <el-icon><ArrowLeft /></el-icon>
          </el-button>
          <h2 v-if="agent">{{ agent.hostname }}</h2>
          <el-tag :type="getStatusType(agent)" size="small" v-if="agent">
            {{ getAgentStatus(agent) }}
          </el-tag>
        </div>
        <div class="header-actions">
          <el-button @click="refreshAgent" :loading="loading" type="primary">
            <el-icon><Refresh /></el-icon>
            Refresh
          </el-button>
          <el-dropdown @command="handleAgentAction" trigger="click">
            <el-button type="success">
              Actions
              <el-icon><ArrowDown /></el-icon>
            </el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="screenshot">Screenshot</el-dropdown-item>
                <el-dropdown-item command="system-info">System Info</el-dropdown-item>
                <el-dropdown-item command="process-list">Process List</el-dropdown-item>
                <el-dropdown-item command="network-info">Network Info</el-dropdown-item>
                <el-dropdown-item divided command="sleep">Configure Sleep</el-dropdown-item>
                <el-dropdown-item command="jitter">Configure Jitter</el-dropdown-item>
                <el-dropdown-item divided command="exit">Exit Agent</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </div>
    </div>

    <div v-if="!agent" class="loading-state">
      <el-icon class="is-loading"><Loading /></el-icon>
      <span>Loading agent details...</span>
    </div>

    <div v-else class="agent-content">
      <!-- Agent Info -->
      <div class="info-section">
        <h3>Agent Information</h3>
        <el-descriptions :column="2" border>
          <el-descriptions-item label="Agent ID">{{ agent.id }}</el-descriptions-item>
          <el-descriptions-item label="Status">
            <el-tag :type="getStatusType(agent)">{{ getAgentStatus(agent) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Hostname">{{ agent.hostname }}</el-descriptions-item>
          <el-descriptions-item label="Username">{{ agent.username }}</el-descriptions-item>
          <el-descriptions-item label="Domain">{{ agent.domain }}</el-descriptions-item>
          <el-descriptions-item label="OS">{{ agent.os }}</el-descriptions-item>
          <el-descriptions-item label="Architecture">{{ agent.arch }}</el-descriptions-item>
          <el-descriptions-item label="Process">{{ agent.process_name }} ({{ agent.process_id }})</el-descriptions-item>
          <el-descriptions-item label="Integrity Level">{{ agent.integrity_level }}</el-descriptions-item>
          <el-descriptions-item label="Remote IP">{{ agent.remote_ip }}</el-descriptions-item>
          <el-descriptions-item label="Internal IP">{{ agent.internal_ip }}</el-descriptions-item>
          <el-descriptions-item label="Sleep Interval">{{ agent.sleep_interval }}s</el-descriptions-item>
          <el-descriptions-item label="Jitter">{{ (agent.jitter * 100).toFixed(0) }}%</el-descriptions-item>
          <el-descriptions-item label="First Seen">{{ formatDate(agent.first_seen) }}</el-descriptions-item>
          <el-descriptions-item label="Last Seen">{{ formatDate(agent.last_seen) }}</el-descriptions-item>
          <el-descriptions-item label="Uptime">{{ getAgentUptime(agent) }}</el-descriptions-item>
        </el-descriptions>
      </div>

      <!-- Command Interface -->
      <div class="command-section">
        <h3>Command Interface</h3>
        <div class="command-input-container">
          <el-input
            v-model="commandInput"
            placeholder="Enter command to execute..."
            @keyup.enter="executeCommand"
            class="command-input"
          >
            <template #append>
              <el-button @click="executeCommand" type="primary" :loading="executing">
                <el-icon><Position /></el-icon>
                Execute
              </el-button>
            </template>
          </el-input>
        </div>

        <!-- Command Templates -->
        <div class="command-templates">
          <h4>Quick Commands</h4>
          <div class="template-grid">
            <div
              v-for="template in commandTemplates"
              :key="template.id"
              class="template-card"
              @click="useTemplate(template)"
            >
              <div class="template-name">{{ template.name }}</div>
              <div class="template-description">{{ template.description }}</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Recent Tasks -->
      <div class="tasks-section">
        <h3>Recent Tasks</h3>
        <div v-if="tasksLoading" class="loading-state">
          <el-icon class="is-loading"><Loading /></el-icon>
          <span>Loading tasks...</span>
        </div>
        <div v-else-if="recentTasks.length === 0" class="empty-state">
          <el-icon><List /></el-icon>
          <span>No tasks yet</span>
        </div>
        <div v-else class="tasks-list">
          <div
            v-for="task in recentTasks"
            :key="task.id"
            class="task-item"
            @click="selectTask(task.id)"
          >
            <div class="task-header">
              <div class="task-command">{{ task.command }}</div>
              <el-tag :type="getStatusType(task.status)" size="small">
                {{ task.status }}
              </el-tag>
            </div>
            <div class="task-meta">
              <span>{{ formatDate(task.created_at) }}</span>
              <span>{{ task.task_type }}</span>
            </div>
            <div v-if="selectedTaskId === task.id && getTaskResult(task.id)" class="task-result">
              <pre>{{ getTaskResult(task.id).output }}</pre>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Sleep Configuration Dialog -->
    <el-dialog
      v-model="sleepDialogVisible"
      title="Configure Sleep Interval"
      width="400px"
    >
      <el-form :model="sleepForm" label-width="120px">
        <el-form-item label="Sleep Time">
          <el-input-number
            v-model="sleepForm.sleepInterval"
            :min="1"
            :max="3600"
            style="width: 100%"
          />
          <div class="form-help">Seconds between check-ins</div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="sleepDialogVisible = false">Cancel</el-button>
        <el-button type="primary" @click="updateSleepConfig">Update</el-button>
      </template>
    </el-dialog>

    <!-- Jitter Configuration Dialog -->
    <el-dialog
      v-model="jitterDialogVisible"
      title="Configure Jitter"
      width="400px"
    >
      <el-form :model="jitterForm" label-width="120px">
        <el-form-item label="Jitter">
          <el-slider
            v-model="jitterForm.jitter"
            :min="0"
            :max="100"
            :step="5"
            show-input
            input-size="small"
          />
          <div class="form-help">Percentage of sleep time to randomize</div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="jitterDialogVisible = false">Cancel</el-button>
        <el-button type="primary" @click="updateJitterConfig">Update</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAgentsStore } from '@/stores/agents'
import { ElMessage, ElMessageBox } from 'element-plus'
import dayjs from 'dayjs'

const route = useRoute()
const router = useRouter()
const agentsStore = useAgentsStore()

const agentId = route.params.id as string
const commandInput = ref('')
const executing = ref(false)
const loading = ref(false)
const tasksLoading = ref(false)
const selectedTaskId = ref('')
const sleepDialogVisible = ref(false)
const jitterDialogVisible = ref(false)

const sleepForm = ref({
  sleepInterval: 30
})

const jitterForm = ref({
  jitter: 20
})

const commandTemplates = ref([
  { id: 'whoami', name: 'Whoami', description: 'Get current user context', command: 'whoami' },
  { id: 'pwd', name: 'Current Directory', description: 'Show current working directory', command: 'pwd' },
  { id: 'ls', name: 'List Files', description: 'List files in current directory', command: 'ls -la' },
  { id: 'ps', name: 'Process List', description: 'Show running processes', command: 'ps aux' },
  { id: 'netstat', name: 'Network Connections', description: 'Show network connections', command: 'netstat -an' },
  { id: 'env', name: 'Environment', description: 'Show environment variables', command: 'env' }
])

let refreshInterval: NodeJS.Timeout | null = null

// Computed properties
const agent = computed(() => agentsStore.selectedAgent)
const recentTasks = computed(() => agentsStore.agentTasks.slice(0, 10))

// Methods
const refreshAgent = async () => {
  try {
    loading.value = true
    await agentsStore.refreshAgent(agentId)
  } catch (error) {
    ElMessage.error('Failed to refresh agent')
  } finally {
    loading.value = false
  }
}

const executeCommand = async () => {
  if (!commandInput.value.trim()) return

  try {
    executing.value = true
    await agentsStore.createTask(agentId, commandInput.value, [], 'Shell')
    ElMessage.success('Command executed')
    commandInput.value = ''
    await loadTasks()
  } catch (error) {
    ElMessage.error('Failed to execute command')
  } finally {
    executing.value = false
  }
}

const useTemplate = (template: any) => {
  commandInput.value = template.command
}

const handleAgentAction = async (command: string) => {
  try {
    switch (command) {
      case 'screenshot':
        await agentsStore.createTask(agentId, 'screenshot', [], 'Screenshot')
        ElMessage.success('Screenshot task created')
        break
      case 'system-info':
        await agentsStore.createTask(agentId, 'systeminfo', [], 'SystemInfo')
        ElMessage.success('System info task created')
        break
      case 'process-list':
        await agentsStore.createTask(agentId, 'tasklist', [], 'ProcessList')
        ElMessage.success('Process list task created')
        break
      case 'network-info':
        await agentsStore.createTask(agentId, 'ipconfig', ['/all'], 'NetworkInfo')
        ElMessage.success('Network info task created')
        break
      case 'sleep':
        if (agent.value) {
          sleepForm.value.sleepInterval = agent.value.sleep_interval
        }
        sleepDialogVisible.value = true
        break
      case 'jitter':
        if (agent.value) {
          jitterForm.value.jitter = agent.value.jitter * 100
        }
        jitterDialogVisible.value = true
        break
      case 'exit':
        await ElMessageBox.confirm(
          'Are you sure you want to terminate this agent?',
          'Exit Agent',
          {
            confirmButtonText: 'Exit',
            cancelButtonText: 'Cancel',
            type: 'warning',
          }
        )
        await agentsStore.createTask(agentId, 'exit', [], 'Exit')
        ElMessage.success('Exit task created')
        break
    }
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error(`Failed to execute ${command}`)
    }
  }
}

const updateSleepConfig = async () => {
  try {
    await agentsStore.createTask(
      agentId,
      'sleep',
      [sleepForm.value.sleepInterval.toString()],
      'Sleep'
    )
    ElMessage.success('Sleep configuration updated')
    sleepDialogVisible.value = false
    await refreshAgent()
  } catch (error) {
    ElMessage.error('Failed to update sleep configuration')
  }
}

const updateJitterConfig = async () => {
  try {
    await agentsStore.createTask(
      agentId,
      'jitter',
      [(jitterForm.value.jitter / 100).toString()],
      'Jitter'
    )
    ElMessage.success('Jitter configuration updated')
    jitterDialogVisible.value = false
    await refreshAgent()
  } catch (error) {
    ElMessage.error('Failed to update jitter configuration')
  }
}

const selectTask = (taskId: string) => {
  selectedTaskId.value = selectedTaskId.value === taskId ? '' : taskId
}

const getTaskResult = (taskId: string) => {
  return agentsStore.agentResults.find(result => result.task_id === taskId)
}

const loadTasks = async () => {
  try {
    tasksLoading.value = true
    await agentsStore.fetchAgentTasks(agentId)
    await agentsStore.fetchAgentResults(agentId)
  } catch (error) {
    // Silent fail
  } finally {
    tasksLoading.value = false
  }
}

const getAgentStatus = (agent: any) => {
  return agentsStore.getAgentStatus(agent)
}

const getStatusType = (status: string) => {
  switch (status) {
    case 'completed': return 'success'
    case 'running': return 'primary'
    case 'pending': return 'warning'
    case 'failed': return 'danger'
    case 'timeout': return 'danger'
    default: return 'info'
  }
}

const formatDate = (dateString: string) => {
  return dayjs(dateString).format('YYYY-MM-DD HH:mm:ss')
}

const getAgentUptime = (agent: any) => {
  return agentsStore.getAgentUptime(agent)
}

const setupAutoRefresh = () => {
  refreshInterval = setInterval(async () => {
    try {
      await refreshAgent()
      await loadTasks()
    } catch (error) {
      // Silent fail for auto-refresh
    }
  }, 30000) // Refresh every 30 seconds
}

const clearAutoRefresh = () => {
  if (refreshInterval) {
    clearInterval(refreshInterval)
    refreshInterval = null
  }
}

// Lifecycle
onMounted(async () => {
  agentsStore.selectAgent(agentId)
  await refreshAgent()
  await loadTasks()
  setupAutoRefresh()
})

onUnmounted(() => {
  clearAutoRefresh()
})
</script>

<style scoped>
.agent-details {
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

.agent-title {
  display: flex;
  align-items: center;
  gap: 12px;
}

.agent-title h2 {
  margin: 0;
  color: var(--el-text-color-primary);
}

.loading-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 20px;
  color: var(--el-text-color-secondary);
  gap: 12px;
}

.agent-content {
  flex: 1;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.info-section,
.command-section,
.tasks-section {
  background: var(--el-bg-color);
  border: 1px solid var(--el-border-color-light);
  border-radius: 8px;
  padding: 20px;
}

.info-section h3,
.command-section h3,
.tasks-section h3 {
  margin: 0 0 16px 0;
  color: var(--el-text-color-primary);
  font-size: 16px;
  font-weight: 600;
}

.command-input-container {
  margin-bottom: 20px;
}

.command-input {
  width: 100%;
}

.command-templates h4 {
  margin: 0 0 12px 0;
  color: var(--el-text-color-primary);
  font-size: 14px;
}

.template-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 12px;
}

.template-card {
  background: var(--el-fill-color-light);
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 6px;
  padding: 12px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.template-card:hover {
  background: var(--el-fill-color);
  border-color: var(--el-color-primary);
}

.template-name {
  font-weight: 500;
  margin-bottom: 4px;
  color: var(--el-text-color-primary);
}

.template-description {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px 20px;
  color: var(--el-text-color-secondary);
  gap: 12px;
}

.tasks-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.task-item {
  background: var(--el-fill-color-light);
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 6px;
  padding: 12px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.task-item:hover {
  background: var(--el-fill-color);
}

.task-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.task-command {
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 13px;
  font-weight: 500;
}

.task-meta {
  display: flex;
  gap: 16px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.task-result {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid var(--el-border-color-lighter);
}

.task-result pre {
  margin: 0;
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.4;
  white-space: pre-wrap;
  word-wrap: break-word;
  background: var(--el-bg-color-page);
  padding: 8px;
  border-radius: 4px;
}

.form-help {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-top: 4px;
}

@media (max-width: 768px) {
  .header-content {
    flex-direction: column;
    gap: 12px;
    align-items: stretch;
  }

  .agent-title {
    flex-direction: column;
    align-items: flex-start;
    gap: 8px;
  }

  .template-grid {
    grid-template-columns: 1fr;
  }

  .task-header {
    flex-direction: column;
    align-items: flex-start;
    gap: 8px;
  }

  .task-meta {
    flex-direction: column;
    gap: 4px;
  }
}
</style>
