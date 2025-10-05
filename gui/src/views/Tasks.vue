<template>
  <div class="tasks-view">
    <!-- Header -->
    <div class="view-header">
      <div class="header-content">
        <h2>Tasks</h2>
        <div class="header-actions">
          <el-button @click="refreshTasks" :loading="tasksLoading" type="primary">
            <el-icon><Refresh /></el-icon>
            Refresh
          </el-button>
          <el-button @click="showCreateTaskDialog" type="success">
            <el-icon><Plus /></el-icon>
            New Task
          </el-button>
        </div>
      </div>
    </div>

    <!-- Agent Selector -->
    <div class="agent-selector">
      <el-select
        v-model="selectedAgentId"
        placeholder="Select an agent"
        style="width: 300px"
        @change="onAgentChange"
      >
        <el-option
          v-for="agent in agentsStore.agents"
          :key="agent.id"
          :label="`${agent.hostname} (${agent.username})`"
          :value="agent.id"
        >
          <div class="agent-option">
            <span>{{ agent.hostname }}</span>
            <el-tag :type="getStatusType(agent)" size="small">
              {{ getAgentStatus(agent) }}
            </el-tag>
          </div>
        </el-option>
      </el-select>
    </div>

    <!-- Tasks List -->
    <div class="tasks-container">
      <div v-if="!selectedAgentId" class="empty-state">
        <el-icon><List /></el-icon>
        <h3>Select an Agent</h3>
        <p>Choose an agent to view and manage tasks</p>
      </div>

      <div v-else-if="tasksLoading" class="loading-state">
        <el-icon class="is-loading"><Loading /></el-icon>
        <span>Loading tasks...</span>
      </div>

      <div v-else-if="filteredTasks.length === 0" class="empty-state">
        <el-icon><List /></el-icon>
        <h3>No tasks found</h3>
        <p>Create a new task to get started</p>
      </div>

      <div v-else class="tasks-list">
        <div
          v-for="task in filteredTasks"
          :key="task.id"
          class="task-item"
          :class="{ selected: selectedTaskId === task.id }"
          @click="selectTask(task.id)"
        >
          <div class="task-header">
            <div class="task-info">
              <div class="task-command">{{ task.command }}</div>
              <div class="task-meta">
                <el-tag :type="getStatusType(task.status)" size="small">
                  {{ task.status }}
                </el-tag>
                <el-tag :type="getPriorityType(task.priority)" size="small">
                  {{ task.priority }}
                </el-tag>
                <span class="task-type">{{ task.task_type }}</span>
              </div>
            </div>
            <div class="task-time">
              {{ formatDate(task.created_at) }}
            </div>
          </div>

          <div v-if="task.arguments.length > 0" class="task-arguments">
            <span class="arguments-label">Arguments:</span>
            <span class="arguments-value">{{ task.arguments.join(' ') }}</span>
          </div>

          <div v-if="selectedTaskId === task.id" class="task-details">
            <div class="task-result" v-if="getTaskResult(task.id)">
              <h4>Result</h4>
              <div class="result-content">
                <div v-if="getTaskResult(task.id).output" class="output">
                  <pre>{{ getTaskResult(task.id).output }}</pre>
                </div>
                <div v-if="getTaskResult(task.id).error" class="error">
                  <strong>Error:</strong>
                  <pre>{{ getTaskResult(task.id).error }}</pre>
                </div>
                <div class="result-meta">
                  <span>Exit Code: {{ getTaskResult(task.id).exit_code || 'N/A' }}</span>
                  <span>Execution Time: {{ getExecutionTimeDisplay(getTaskResult(task.id)) }}</span>
                </div>
              </div>
            </div>
            <div v-else-if="task.status === 'completed'" class="no-result">
              <el-icon><Warning /></el-icon>
              <span>No result data available</span>
            </div>
            <div v-else class="pending-status">
              <el-icon v-if="task.status === 'running'" class="is-loading"><Loading /></el-icon>
              <el-icon v-else><Clock /></el-icon>
              <span>{{ getStatusMessage(task.status) }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Create Task Dialog -->
    <el-dialog
      v-model="createTaskDialogVisible"
      title="Create New Task"
      width="600px"
    >
      <el-form :model="taskForm" label-width="100px">
        <el-form-item label="Command">
          <el-input
            v-model="taskForm.command"
            placeholder="Enter command..."
            required
          />
        </el-form-item>

        <el-form-item label="Arguments">
          <el-input
            v-model="taskForm.argumentsText"
            type="textarea"
            :rows="3"
            placeholder="Enter arguments (one per line or space-separated)..."
          />
        </el-form-item>

        <el-form-item label="Task Type">
          <el-select v-model="taskForm.taskType" style="width: 100%">
            <el-option label="Shell" value="Shell" />
            <el-option label="PowerShell" value="PowerShell" />
            <el-option label="Download" value="Download" />
            <el-option label="Upload" value="Upload" />
            <el-option label="Screenshot" value="Screenshot" />
            <el-option label="Process List" value="ProcessList" />
            <el-option label="System Info" value="SystemInfo" />
            <el-option label="Network Info" value="NetworkInfo" />
            <el-option label="File List" value="FileList" />
            <el-option label="Registry" value="Registry" />
            <el-option label="Sleep" value="Sleep" />
            <el-option label="Exit" value="Exit" />
          </el-select>
        </el-form-item>

        <el-form-item label="Priority">
          <el-select v-model="taskForm.priority" style="width: 100%">
            <el-option label="Low" value="Low" />
            <el-option label="Normal" value="Normal" />
            <el-option label="High" value="High" />
            <el-option label="Critical" value="Critical" />
          </el-select>
        </el-form-item>
      </el-form>

      <template #footer>
        <span class="dialog-footer">
          <el-button @click="createTaskDialogVisible = false">Cancel</el-button>
          <el-button type="primary" @click="createTask" :loading="creatingTask">
            Create Task
          </el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useAgentsStore } from '@/stores/agents'
import { useConnectionStore } from '@/stores/connection'
import { ElMessage } from 'element-plus'
import dayjs from 'dayjs'

const agentsStore = useAgentsStore()
const connectionStore = useConnectionStore()

const selectedAgentId = ref('')
const selectedTaskId = ref('')
const tasksLoading = ref(false)
const creatingTask = ref(false)
const createTaskDialogVisible = ref(false)

const taskForm = ref({
  command: '',
  argumentsText: '',
  taskType: 'Shell',
  priority: 'Normal'
})

let refreshInterval: NodeJS.Timeout | null = null

// Computed properties
const filteredTasks = computed(() => {
  return agentsStore.agentTasks
})

const taskResults = computed(() => {
  return agentsStore.agentResults
})

// Methods
const refreshTasks = async () => {
  if (!selectedAgentId.value) return

  try {
    tasksLoading.value = true
    await Promise.all([
      agentsStore.fetchAgentTasks(selectedAgentId.value),
      agentsStore.fetchAgentResults(selectedAgentId.value)
    ])
  } catch (error) {
    ElMessage.error('Failed to refresh tasks')
  } finally {
    tasksLoading.value = false
  }
}

const onAgentChange = async (agentId: string) => {
  if (agentId) {
    await refreshTasks()
  }
}

const selectTask = (taskId: string) => {
  selectedTaskId.value = selectedTaskId.value === taskId ? '' : taskId
}

const showCreateTaskDialog = () => {
  if (!selectedAgentId.value) {
    ElMessage.warning('Please select an agent first')
    return
  }

  taskForm.value = {
    command: '',
    argumentsText: '',
    taskType: 'Shell',
    priority: 'Normal'
  }
  createTaskDialogVisible.value = true
}

const createTask = async () => {
  if (!selectedAgentId.value) return

  try {
    creatingTask.value = true

    const taskArguments = taskForm.value.argumentsText
      .split(/\s+/)
      .filter(arg => arg.trim())

    await agentsStore.createTask(
      selectedAgentId.value,
      taskForm.value.command,
      taskArguments,
      taskForm.value.taskType
    )

    ElMessage.success('Task created successfully')
    createTaskDialogVisible.value = false
    await refreshTasks()
  } catch (error) {
    ElMessage.error(`Failed to create task: ${error}`)
  } finally {
    creatingTask.value = false
  }
}

const getTaskResult = (taskId: string) => {
  return taskResults.value.find(result => result.task_id === taskId)
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

const getPriorityType = (priority: string) => {
  switch (priority) {
    case 'critical': return 'danger'
    case 'high': return 'warning'
    case 'normal': return 'primary'
    case 'low': return 'info'
    default: return 'info'
  }
}

const getStatusMessage = (status: string) => {
  switch (status) {
    case 'pending': return 'Waiting to be assigned...'
    case 'assigned': return 'Task assigned to agent'
    case 'running': return 'Task is executing...'
    case 'completed': return 'Task completed successfully'
    case 'failed': return 'Task failed'
    case 'timeout': return 'Task timed out'
    default: return 'Unknown status'
  }
}

const getExecutionTimeDisplay = (result: any) => {
  if (!result.execution_time) return 'N/A'

  if (result.execution_time < 1000) {
    return `${result.execution_time.toFixed(0)}ms`
  } else {
    return `${(result.execution_time / 1000).toFixed(2)}s`
  }
}

const formatDate = (dateString: string) => {
  return dayjs(dateString).format('YYYY-MM-DD HH:mm:ss')
}

const setupAutoRefresh = () => {
  if (connectionStore.autoRefresh && connectionStore.isConnected && selectedAgentId.value) {
    refreshInterval = setInterval(async () => {
      try {
        await refreshTasks()
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
  if (agentsStore.agents.length > 0 && !selectedAgentId.value) {
    selectedAgentId.value = agentsStore.agents[0].id
    await refreshTasks()
  }
})

onUnmounted(() => {
  clearAutoRefresh()
})

// Watch for agent changes
const unwatchAgent = selectedAgentId.watch(async (newAgentId) => {
  clearAutoRefresh()
  if (newAgentId) {
    setupAutoRefresh()
  }
})
</script>

<style scoped>
.tasks-view {
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

.agent-selector {
  margin-bottom: 20px;
}

.agent-option {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
}

.tasks-container {
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

.tasks-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.task-item {
  background: var(--el-bg-color);
  border: 1px solid var(--el-border-color-light);
  border-radius: 8px;
  padding: 16px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.task-item:hover {
  border-color: var(--el-border-color);
}

.task-item.selected {
  border-color: var(--el-color-primary);
  background: var(--el-color-primary-light-9);
}

.task-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.task-info {
  flex: 1;
}

.task-command {
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 14px;
  font-weight: 500;
  color: var(--el-text-color-primary);
  margin-bottom: 8px;
}

.task-meta {
  display: flex;
  align-items: center;
  gap: 8px;
}

.task-type {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.task-time {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.task-arguments {
  display: flex;
  gap: 8px;
  font-size: 12px;
  margin-bottom: 8px;
}

.arguments-label {
  color: var(--el-text-color-secondary);
}

.arguments-value {
  color: var(--el-text-color-primary);
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
}

.task-details {
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid var(--el-border-color-lighter);
}

.task-result h4 {
  margin: 0 0 12px 0;
  color: var(--el-text-color-primary);
}

.result-content {
  background: var(--el-bg-color-page);
  border-radius: 6px;
  padding: 12px;
}

.output pre,
.error pre {
  margin: 0;
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.5;
  white-space: pre-wrap;
  word-wrap: break-word;
}

.output pre {
  color: var(--el-text-color-primary);
}

.error pre {
  color: var(--el-color-danger);
}

.result-meta {
  display: flex;
  gap: 16px;
  margin-top: 8px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.no-result,
.pending-status {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--el-text-color-secondary);
  font-size: 14px;
}

.no-result .el-icon,
.pending-status .el-icon {
  font-size: 16px;
}

@media (max-width: 768px) {
  .header-content {
    flex-direction: column;
    gap: 12px;
    align-items: stretch;
  }

  .agent-selector .el-select {
    width: 100% !important;
  }

  .task-header {
    flex-direction: column;
    gap: 8px;
  }

  .task-meta {
    flex-wrap: wrap;
  }

  .result-meta {
    flex-direction: column;
    gap: 4px;
  }
}
</style>
