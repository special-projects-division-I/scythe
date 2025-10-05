<template>
  <div class="main-layout">
    <!-- Header -->
    <header class="header">
      <div class="flex items-center gap-4">
        <h1 class="text-xl font-bold text-primary">SCYTHE C2 Controller</h1>
        <div class="connection-status" :class="connectionStatusClass">
          <el-icon><Connection v-if="isConnected" /><Close v-else /></el-icon>
          <span>{{ connectionStatusText }}</span>
        </div>
      </div>

      <div class="flex items-center gap-4">
        <el-button @click="showConnectionDialog" :type="isConnected ? 'success' : 'danger'" size="small">
          <el-icon><Setting /></el-icon>
          Connection
        </el-button>

        <el-dropdown @command="handleThemeCommand">
          <el-button size="small" text>
            <el-icon><Sunny v-if="isDark" /><Moon v-else /></el-icon>
          </el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="light">Light</el-dropdown-item>
              <el-dropdown-item command="dark">Dark</el-dropdown-item>
              <el-dropdown-item command="auto">Auto</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>
    </header>

    <!-- Main Content -->
    <div class="content">
      <!-- Sidebar -->
      <aside class="sidebar">
        <el-menu
          :default-active="$route.path"
          router
          :collapse="false"
          background-color="var(--el-bg-color)"
          text-color="var(--el-text-color-primary)"
          active-text-color="var(--el-color-primary)"
        >
          <el-menu-item index="/dashboard">
            <el-icon><Monitor /></el-icon>
            <span>Dashboard</span>
          </el-menu-item>

          <el-menu-item index="/agents">
            <el-icon><User /></el-icon>
            <span>Agents</span>
          </el-menu-item>

          <el-menu-item index="/tasks">
            <el-icon><List /></el-icon>
            <span>Tasks</span>
          </el-menu-item>

          <el-menu-item index="/files">
            <el-icon><Folder /></el-icon>
            <span>File Manager</span>
          </el-menu-item>

          <el-menu-item index="/logs">
            <el-icon><Document /></el-icon>
            <span>Activity Logs</span>
          </el-menu-item>

          <el-menu-item index="/settings">
            <el-icon><Setting /></el-icon>
            <span>Settings</span>
          </el-menu-item>
        </el-menu>
      </aside>

      <!-- Main Content Area -->
      <main class="main-content">
        <router-view />
      </main>
    </div>

    <!-- Connection Dialog -->
    <el-dialog
      v-model="connectionDialogVisible"
      title="Server Connection"
      width="500px"
    >
      <el-form :model="connectionForm" label-width="100px">
        <el-form-item label="Server URL">
          <el-input
            v-model="connectionForm.url"
            placeholder="http://127.0.0.1:8080"
          />
        </el-form-item>

        <el-form-item label="Username">
          <el-input v-model="connectionForm.username" placeholder="Optional" />
        </el-form-item>

        <el-form-item label="Password">
          <el-input
            v-model="connectionForm.password"
            type="password"
            placeholder="Optional"
            show-password
          />
        </el-form-item>
      </el-form>

      <template #footer>
        <span class="dialog-footer">
          <el-button @click="connectionDialogVisible = false">Cancel</el-button>
          <el-button
            type="primary"
            @click="handleConnection"
            :loading="connecting"
          >
            {{ isConnected ? 'Disconnect' : 'Connect' }}
          </el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useConnectionStore } from '@/stores/connection'
import { ElMessage } from 'element-plus'
import { invoke } from '@tauri-apps/api/tauri'

const connectionStore = useConnectionStore()

const connectionDialogVisible = ref(false)
const connecting = ref(false)

const connectionForm = ref({
  url: 'http://127.0.0.1:8080',
  username: '',
  password: ''
})

const isConnected = computed(() => connectionStore.isConnected)
const connectionStatusClass = computed(() => {
  if (connectionStore.status === 'connected') return 'connection-connected'
  if (connectionStore.status === 'connecting') return 'connection-connecting'
  return 'connection-disconnected'
})

const connectionStatusText = computed(() => {
  switch (connectionStore.status) {
    case 'connected': return `Connected to ${connectionStore.serverUrl}`
    case 'connecting': return 'Connecting...'
    case 'disconnected': return 'Disconnected'
    default: return 'Unknown'
  }
})

const isDark = ref(true)

const showConnectionDialog = () => {
  connectionForm.value.url = connectionStore.serverUrl || 'http://127.0.0.1:8080'
  connectionDialogVisible.value = true
}

const handleConnection = async () => {
  connecting.value = true

  try {
    if (isConnected.value) {
      await connectionStore.disconnect()
      ElMessage.success('Disconnected from server')
    } else {
      await connectionStore.connect(
        connectionForm.value.url,
        connectionForm.value.username || undefined,
        connectionForm.value.password || undefined
      )
      ElMessage.success('Connected to server')
    }
    connectionDialogVisible.value = false
  } catch (error) {
    ElMessage.error(`Connection failed: ${error}`)
  } finally {
    connecting.value = false
  }
}

const handleThemeCommand = (command: string) => {
  if (command === 'light') {
    document.documentElement.classList.remove('dark')
    isDark.value = false
  } else if (command === 'dark') {
    document.documentElement.classList.add('dark')
    isDark.value = true
  } else {
    // Auto - detect system preference
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
    if (prefersDark) {
      document.documentElement.classList.add('dark')
      isDark.value = true
    } else {
      document.documentElement.classList.remove('dark')
      isDark.value = false
    }
  }
}

onMounted(() => {
  // Initialize dark mode
  handleThemeCommand('dark')

  // Load settings and try to connect
  connectionStore.loadSettings().then(() => {
    if (connectionStore.autoConnect) {
      connectionStore.connect().catch(() => {
        // Silent fail on auto-connect
      })
    }
  })
})
</script>

<style scoped>
.main-layout {
  height: 100vh;
  display: flex;
  flex-direction: column;
}

.header {
  background: var(--el-bg-color);
  border-bottom: 1px solid var(--el-border-color-light);
  padding: 0 20px;
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.content {
  flex: 1;
  display: flex;
  overflow: hidden;
}

.sidebar {
  width: 250px;
  background: var(--el-bg-color);
  border-right: 1px solid var(--el-border-color-light);
  overflow-y: auto;
}

.main-content {
  flex: 1;
  overflow-y: auto;
  padding: 20px;
}

.connection-status {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  border-radius: 20px;
  font-size: 13px;
  font-weight: 500;
}

.connection-connected {
  background: var(--el-color-success-light-9);
  color: var(--el-color-success);
}

.connection-disconnected {
  background: var(--el-color-danger-light-9);
  color: var(--el-color-danger);
}

.connection-connecting {
  background: var(--el-color-warning-light-9);
  color: var(--el-color-warning);
}

.text-primary {
  color: var(--el-color-primary);
}
</style>
