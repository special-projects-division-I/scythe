<template>
  <div class="files-view">
    <!-- Header -->
    <div class="view-header">
      <div class="header-content">
        <h2>File Manager</h2>
        <div class="header-actions">
          <el-button @click="refreshFiles" :loading="loading" type="primary">
            <el-icon><Refresh /></el-icon>
            Refresh
          </el-button>
          <el-button @click="showUploadDialog" type="success">
            <el-icon><Upload /></el-icon>
            Upload File
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

      <el-input
        v-model="currentPath"
        placeholder="File path"
        style="width: 400px; margin-left: 12px"
        @keyup.enter="listFiles"
      >
        <template #append>
          <el-button @click="listFiles" :loading="loading">
            <el-icon><Search /></el-icon>
          </el-button>
        </template>
      </el-input>
    </div>

    <!-- File Browser -->
    <div class="file-browser">
      <div v-if="!selectedAgentId" class="empty-state">
        <el-icon><Folder /></el-icon>
        <h3>Select an Agent</h3>
        <p>Choose an agent to browse files</p>
      </div>

      <div v-else-if="loading" class="loading-state">
        <el-icon class="is-loading"><Loading /></el-icon>
        <span>Loading files...</span>
      </div>

      <div v-else class="file-content">
        <!-- Path Navigation -->
        <div class="path-navigation">
          <el-breadcrumb separator="/">
            <el-breadcrumb-item @click="navigatePath('')" style="cursor: pointer">
              <el-icon><House /></el-icon>
            </el-breadcrumb-item>
            <el-breadcrumb-item
              v-for="(segment, index) in pathSegments"
              :key="index"
              @click="navigateToSegment(index)"
              style="cursor: pointer"
            >
              {{ segment }}
            </el-breadcrumb-item>
          </el-breadcrumb>
        </div>

        <!-- File List -->
        <div class="file-list">
          <div v-if="files.length === 0" class="empty-state">
            <el-icon><FolderOpened /></el-icon>
            <h3>No files found</h3>
            <p>The directory is empty or doesn't exist</p>
          </div>

          <div v-else class="file-grid">
            <!-- Directory Up -->
            <div
              v-if="currentPath !== ''"
              class="file-item directory"
              @click="navigateUp"
            >
              <div class="file-icon">
                <el-icon><ArrowUp /></el-icon>
              </div>
              <div class="file-info">
                <div class="file-name">..</div>
                <div class="file-details">Parent Directory</div>
              </div>
            </div>

            <!-- Directories -->
            <div
              v-for="file in directories"
              :key="file.name"
              class="file-item directory"
              @click="enterDirectory(file.name)"
            >
              <div class="file-icon">
                <el-icon><Folder /></el-icon>
              </div>
              <div class="file-info">
                <div class="file-name">{{ file.name }}</div>
                <div class="file-details">Directory</div>
              </div>
              <div class="file-actions">
                <el-dropdown @command="(cmd) => handleFileAction(cmd, file)" trigger="click">
                  <el-button size="small" text>
                    <el-icon><MoreFilled /></el-icon>
                  </el-button>
                  <template #dropdown>
                    <el-dropdown-menu>
                      <el-dropdown-item command="delete">Delete</el-dropdown-item>
                    </el-dropdown-menu>
                  </template>
                </el-dropdown>
              </div>
            </div>

            <!-- Files -->
            <div
              v-for="file in regularFiles"
              :key="file.name"
              class="file-item file"
              @click="selectFile(file)"
            >
              <div class="file-icon">
                <el-icon><Document /></el-icon>
              </div>
              <div class="file-info">
                <div class="file-name">{{ file.name }}</div>
                <div class="file-details">
                  {{ formatFileSize(file.size) }} • {{ formatDate(file.modified) }}
                </div>
              </div>
              <div class="file-actions">
                <el-dropdown @command="(cmd) => handleFileAction(cmd, file)" trigger="click">
                  <el-button size="small" text>
                    <el-icon><MoreFilled /></el-icon>
                  </el-button>
                  <template #dropdown>
                    <el-dropdown-menu>
                      <el-dropdown-item command="download">Download</el-dropdown-item>
                      <el-dropdown-item command="view">View</el-dropdown-item>
                      <el-dropdown-item divided command="delete">Delete</el-dropdown-item>
                    </el-dropdown-menu>
                  </template>
                </el-dropdown>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Upload Dialog -->
    <el-dialog
      v-model="uploadDialogVisible"
      title="Upload File"
      width="500px"
    >
      <el-form :model="uploadForm" label-width="100px">
        <el-form-item label="Local File">
          <el-input
            v-model="uploadForm.localPath"
            placeholder="Select a file to upload"
            readonly
          >
            <template #append>
              <el-button @click="selectLocalFile">Browse</el-button>
            </template>
          </el-input>
        </el-form-item>

        <el-form-item label="Remote Path">
          <el-input
            v-model="uploadForm.remotePath"
            :placeholder="currentPath || 'Enter remote path'"
          />
        </el-form-item>
      </el-form>

      <template #footer>
        <span class="dialog-footer">
          <el-button @click="uploadDialogVisible = false">Cancel</el-button>
          <el-button type="primary" @click="uploadFile" :loading="uploading">
            Upload
          </el-button>
        </span>
      </template>
    </el-dialog>

    <!-- File View Dialog -->
    <el-dialog
      v-model="viewDialogVisible"
      :title="`View File: ${selectedFile?.name}`"
      width="80%"
      top="5vh"
    >
      <div class="file-viewer">
        <div v-if="fileContent" class="file-content">
          <pre>{{ fileContent }}</pre>
        </div>
        <div v-else-if="loadingContent" class="loading-content">
          <el-icon class="is-loading"><Loading /></el-icon>
          <span>Loading file content...</span>
        </div>
        <div v-else class="error-content">
          <el-icon><Warning /></el-icon>
          <span>Failed to load file content</span>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useAgentsStore } from '@/stores/agents'
import { ElMessage, ElMessageBox } from 'element-plus'
import { invoke } from '@tauri-apps/api/tauri'
import dayjs from 'dayjs'

const agentsStore = useAgentsStore()

const selectedAgentId = ref('')
const currentPath = ref('')
const files = ref<any[]>([])
const loading = ref(false)
const uploadDialogVisible = ref(false)
const viewDialogVisible = ref(false)
const uploading = ref(false)
const loadingContent = ref(false)
const fileContent = ref('')
const selectedFile = ref<any>(null)

const uploadForm = ref({
  localPath: '',
  remotePath: ''
})

// Computed properties
const pathSegments = computed(() => {
  return currentPath.value.split('/').filter(segment => segment !== '')
})

const directories = computed(() => {
  return files.value.filter(file => file.type === 'directory')
})

const regularFiles = computed(() => {
  return files.value.filter(file => file.type === 'file')
})

// Methods
const refreshFiles = async () => {
  if (!selectedAgentId.value) return
  await listFiles()
}

const onAgentChange = async () => {
  currentPath.value = ''
  await listFiles()
}

const listFiles = async () => {
  if (!selectedAgentId.value) return

  try {
    loading.value = true

    // Create a task to list files
    await agentsStore.createTask(
      selectedAgentId.value,
      'ls',
      ['-la', currentPath.value || '.'],
      'FileList'
    )

    ElMessage.success('File list task created')

    // In a real implementation, we would wait for the result
    // For now, simulate a file listing
    setTimeout(() => {
      files.value = [
        { name: 'Documents', type: 'directory', size: 0, modified: '2024-01-15T10:30:00Z' },
        { name: 'Downloads', type: 'directory', size: 0, modified: '2024-01-10T15:45:00Z' },
        { name: 'Desktop', type: 'directory', size: 0, modified: '2024-01-20T09:15:00Z' },
        { name: 'report.txt', type: 'file', size: 1024, modified: '2024-01-18T14:20:00Z' },
        { name: 'config.json', type: 'file', size: 512, modified: '2024-01-12T11:30:00Z' },
        { name: 'script.ps1', type: 'file', size: 2048, modified: '2024-01-22T16:45:00Z' }
      ]
    }, 1000)
  } catch (error) {
    ElMessage.error('Failed to list files')
  } finally {
    loading.value = false
  }
}

const navigatePath = (path: string) => {
  currentPath.value = path
  listFiles()
}

const navigateToSegment = (index: number) => {
  const segments = pathSegments.value.slice(0, index + 1)
  currentPath.value = segments.join('/')
  listFiles()
}

const navigateUp = () => {
  const segments = pathSegments.value
  segments.pop()
  currentPath.value = segments.join('/')
  listFiles()
}

const enterDirectory = (dirname: string) => {
  const newPath = currentPath.value ? `${currentPath.value}/${dirname}` : dirname
  currentPath.value = newPath
  listFiles()
}

const selectFile = (file: any) => {
  selectedFile.value = file
}

const handleFileAction = async (command: string, file: any) => {
  try {
    switch (command) {
      case 'download':
        await downloadFile(file)
        break
      case 'view':
        await viewFile(file)
        break
      case 'delete':
        await deleteFile(file)
        break
    }
  } catch (error) {
    ElMessage.error(`Failed to ${command} file: ${error}`)
  }
}

const downloadFile = async (file: any) => {
  try {
    const filePath = currentPath.value ? `${currentPath.value}/${file.name}` : file.name

    // Create download task
    await agentsStore.createTask(
      selectedAgentId.value,
      'download',
      [filePath],
      'Download'
    )

    ElMessage.success('Download task created')
  } catch (error) {
    throw error
  }
}

const viewFile = async (file: any) => {
  try {
    selectedFile.value = file
    viewDialogVisible.value = true
    loadingContent.value = true

    const filePath = currentPath.value ? `${currentPath.value}/${file.name}` : file.name

    // Create view task
    await agentsStore.createTask(
      selectedAgentId.value,
      'cat',
      [filePath],
      'Shell'
    )

    // Simulate file content
    setTimeout(() => {
      fileContent.value = `This is the content of ${file.name}\n\nFile size: ${formatFileSize(file.size)}\nLast modified: ${formatDate(file.modified)}\n\n[File content would be displayed here in a real implementation]`
      loadingContent.value = false
    }, 1000)
  } catch (error) {
    loadingContent.value = false
    throw error
  }
}

const deleteFile = async (file: any) => {
  try {
    await ElMessageBox.confirm(
      `Are you sure you want to delete ${file.name}?`,
      'Delete File',
      {
        confirmButtonText: 'Delete',
        cancelButtonText: 'Cancel',
        type: 'warning',
      }
    )

    const filePath = currentPath.value ? `${currentPath.value}/${file.name}` : file.name

    await agentsStore.createTask(
      selectedAgentId.value,
      'rm',
      [filePath],
      'Shell'
    )

    ElMessage.success('Delete task created')
    await listFiles()
  } catch (error) {
    if (error !== 'cancel') {
      throw error
    }
  }
}

const showUploadDialog = () => {
  if (!selectedAgentId.value) {
    ElMessage.warning('Please select an agent first')
    return
  }

  uploadForm.value = {
    localPath: '',
    remotePath: currentPath.value
  }
  uploadDialogVisible.value = true
}

const selectLocalFile = async () => {
  try {
    const selected = await invoke('show_file_dialog', {
      dialogType: 'open_file',
      title: 'Select File to Upload',
      defaultPath: null,
      filters: null
    })

    if (selected) {
      uploadForm.value.localPath = selected as string
    }
  } catch (error) {
    ElMessage.error('Failed to select file')
  }
}

const uploadFile = async () => {
  try {
    uploading.value = true

    await invoke('upload_file', {
      agentId: selectedAgentId.value,
      localPath: uploadForm.value.localPath,
      remotePath: uploadForm.value.remotePath
    })

    ElMessage.success('File uploaded successfully')
    uploadDialogVisible.value = false
    await listFiles()
  } catch (error) {
    ElMessage.error(`Failed to upload file: ${error}`)
  } finally {
    uploading.value = false
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

const formatFileSize = (bytes: number) => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

const formatDate = (dateString: string) => {
  return dayjs(dateString).format('YYYY-MM-DD HH:mm')
}

// Lifecycle
onMounted(async () => {
  if (agentsStore.agents.length > 0 && !selectedAgentId.value) {
    selectedAgentId.value = agentsStore.agents[0].id
    await listFiles()
  }
})
</script>

<style scoped>
.files-view {
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
  display: flex;
  align-items: center;
  margin-bottom: 20px;
  gap: 12px;
}

.agent-option {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
}

.file-browser {
  flex: 1;
  overflow: hidden;
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

.file-content {
  height: 100%;
  display: flex;
  flex-direction: column;
}

.path-navigation {
  padding: 12px 16px;
  background: var(--el-fill-color-light);
  border-bottom: 1px solid var(--el-border-color-light);
}

.file-list {
  flex: 1;
  overflow-y: auto;
  padding: 16px;
}

.file-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 12px;
}

.file-item {
  background: var(--el-bg-color);
  border: 1px solid var(--el-border-color-light);
  border-radius: 8px;
  padding: 16px;
  cursor: pointer;
  transition: all 0.2s ease;
  display: flex;
  flex-direction: column;
  position: relative;
}

.file-item:hover {
  border-color: var(--el-color-primary);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.file-item.directory {
  background: var(--el-color-primary-light-9);
}

.file-icon {
  font-size: 32px;
  color: var(--el-color-primary);
  margin-bottom: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.file-item.directory .file-icon {
  color: var(--el-color-warning);
}

.file-info {
  flex: 1;
}

.file-name {
  font-weight: 500;
  color: var(--el-text-color-primary);
  margin-bottom: 4px;
  word-break: break-all;
}

.file-details {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.file-actions {
  position: absolute;
  top: 8px;
  right: 8px;
  opacity: 0;
  transition: opacity 0.2s ease;
}

.file-item:hover .file-actions {
  opacity: 1;
}

.file-viewer {
  height: 70vh;
  overflow: hidden;
}

.file-content pre {
  height: 100%;
  overflow-y: auto;
  margin: 0;
  padding: 16px;
  background: var(--el-fill-color-light);
  border-radius: 6px;
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 13px;
  line-height: 1.5;
  white-space: pre-wrap;
  word-wrap: break-word;
}

.loading-content,
.error-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 200px;
  color: var(--el-text-color-secondary);
  gap: 12px;
}

@media (max-width: 768px) {
  .header-content {
    flex-direction: column;
    gap: 12px;
    align-items: stretch;
  }

  .agent-selector {
    flex-direction: column;
    align-items: stretch;
  }

  .agent-selector .el-input {
    width: 100% !important;
    margin-left: 0 !important;
  }

  .file-grid {
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  }
}
</style>
