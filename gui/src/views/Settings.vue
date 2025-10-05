<template>
  <div class="settings-view">
    <!-- Header -->
    <div class="view-header">
      <div class="header-content">
        <h2>Settings</h2>
        <div class="header-actions">
          <el-button @click="resetSettings" type="danger">
            <el-icon><RefreshLeft /></el-icon>
            Reset to Defaults
          </el-button>
          <el-button @click="saveSettings" type="primary" :loading="saving">
            <el-icon><Check /></el-icon>
            Save Settings
          </el-button>
        </div>
      </div>
    </div>

    <div class="settings-content">
      <el-tabs v-model="activeTab" type="card">
        <!-- Connection Settings -->
        <el-tab-pane label="Connection" name="connection">
          <div class="settings-section">
            <h3>Server Connection</h3>
            <el-form :model="settings" label-width="200px">
              <el-form-item label="Server URL">
                <el-input
                  v-model="settings.server_url"
                  placeholder="http://127.0.0.1:8080"
                  style="width: 400px"
                />
                <div class="form-help">The URL of the SCYTHE C2 server</div>
              </el-form-item>

              <el-form-item label="Auto Connect">
                <el-switch
                  v-model="settings.auto_connect"
                  active-text="Enabled"
                  inactive-text="Disabled"
                />
                <div class="form-help">Automatically connect to server on startup</div>
              </el-form-item>

              <el-form-item label="Connection Timeout">
                <el-input-number
                  v-model="settings.connection_timeout"
                  :min="5"
                  :max="60"
                  :step="5"
                  style="width: 200px"
                />
                <span class="input-suffix">seconds</span>
                <div class="form-help">Timeout for server connection attempts</div>
              </el-form-item>

              <el-form-item label="Retry Attempts">
                <el-input-number
                  v-model="settings.retry_attempts"
                  :min="0"
                  :max="10"
                  :step="1"
                  style="width: 200px"
                />
                <div class="form-help">Number of connection retry attempts</div>
              </el-form-item>
            </el-form>
          </div>
        </el-tab-pane>

        <!-- Refresh Settings -->
        <el-tab-pane label="Auto Refresh" name="refresh">
          <div class="settings-section">
            <h3>Auto Refresh</h3>
            <el-form :model="settings" label-width="200px">
              <el-form-item label="Enable Auto Refresh">
                <el-switch
                  v-model="settings.auto_refresh"
                  active-text="Enabled"
                  inactive-text="Disabled"
                />
                <div class="form-help">Automatically refresh data from server</div>
              </el-form-item>

              <el-form-item label="Refresh Interval" v-if="settings.auto_refresh">
                <el-input-number
                  v-model="settings.refresh_interval"
                  :min="10"
                  :max="300"
                  :step="10"
                  style="width: 200px"
                />
                <span class="input-suffix">seconds</span>
                <div class="form-help">How often to refresh data from server</div>
              </el-form-item>

              <el-form-item label="Refresh on Focus">
                <el-switch
                  v-model="settings.refresh_on_focus"
                  active-text="Enabled"
                  inactive-text="Disabled"
                />
                <div class="form-help">Refresh data when window gains focus</div>
              </el-form-item>
            </el-form>
          </div>
        </el-tab-pane>

        <!-- Appearance Settings -->
        <el-tab-pane label="Appearance" name="appearance">
          <div class="settings-section">
            <h3>Theme</h3>
            <el-form :model="settings" label-width="200px">
              <el-form-item label="Theme">
                <el-radio-group v-model="settings.theme">
                  <el-radio label="dark">Dark</el-radio>
                  <el-radio label="light">Light</el-radio>
                  <el-radio label="auto">Auto (System)</el-radio>
                </el-radio-group>
                <div class="form-help">Choose your preferred color theme</div>
              </el-form-item>

              <el-form-item label="Font Size">
                <el-slider
                  v-model="settings.font_size"
                  :min="12"
                  :max="20"
                  :step="1"
                  show-input
                  input-size="small"
                  style="width: 400px"
                />
                <div class="form-help">Adjust the base font size</div>
              </el-form-item>

              <el-form-item label="Compact Mode">
                <el-switch
                  v-model="settings.compact_mode"
                  active-text="Enabled"
                  inactive-text="Disabled"
                />
                <div class="form-help">Use more compact layout to save space</div>
              </el-form-item>
            </el-form>
          </div>
        </el-tab-pane>

        <!-- Notification Settings -->
        <el-tab-pane label="Notifications" name="notifications">
          <div class="settings-section">
            <h3>System Notifications</h3>
            <el-form :model="settings" label-width="200px">
              <el-form-item label="Enable Notifications">
                <el-switch
                  v-model="settings.notifications_enabled"
                  active-text="Enabled"
                  inactive-text="Disabled"
                />
                <div class="form-help">Show system notifications for important events</div>
              </el-form-item>

              <el-form-item label="Agent Connection" v-if="settings.notifications_enabled">
                <el-switch
                  v-model="settings.notify_agent_connection"
                  active-text="Enabled"
                  inactive-text="Disabled"
                />
                <div class="form-help">Notify when agents connect or disconnect</div>
              </el-form-item>

              <el-form-item label="Task Completion" v-if="settings.notifications_enabled">
                <el-switch
                  v-model="settings.notify_task_completion"
                  active-text="Enabled"
                  inactive-text="Disabled"
                />
                <div class="form-help">Notify when tasks complete or fail</div>
              </el-form-item>

              <el-form-item label="Sound Effects" v-if="settings.notifications_enabled">
                <el-switch
                  v-model="settings.sound_effects"
                  active-text="Enabled"
                  inactive-text="Disabled"
                />
                <div class="form-help">Play sound effects with notifications</div>
              </el-form-item>
            </el-form>
          </div>
        </el-tab-pane>

        <!-- Security Settings -->
        <el-tab-pane label="Security" name="security">
          <div class="settings-section">
            <h3>Security</h3>
            <el-form :model="settings" label-width="200px">
              <el-form-item label="Session Timeout">
                <el-input-number
                  v-model="settings.session_timeout"
                  :min="0"
                  :max="480"
                  :step="30"
                  style="width: 200px"
                />
                <span class="input-suffix">minutes (0 = never)</span>
                <div class="form-help">Automatically lock session after inactivity</div>
              </el-form-item>

              <el-form-item label="Require Authentication">
                <el-switch
                  v-model="settings.require_auth"
                  active-text="Enabled"
                  inactive-text="Disabled"
                />
                <div class="form-help">Require authentication for server connection</div>
              </el-form-item>

              <el-form-item label="Encrypt Local Data">
                <el-switch
                  v-model="settings.encrypt_local_data"
                  active-text="Enabled"
                  inactive-text="Disabled"
                />
                <div class="form-help">Encrypt locally stored data and settings</div>
              </el-form-item>

              <el-form-item label="Clear Clipboard on Exit">
                <el-switch
                  v-model="settings.clear_clipboard"
                  active-text="Enabled"
                  inactive-text="Disabled"
                />
                <div class="form-help">Clear clipboard when application exits</div>
              </el-form-item>
            </el-form>
          </div>
        </el-tab-pane>

        <!-- Advanced Settings -->
        <el-tab-pane label="Advanced" name="advanced">
          <div class="settings-section">
            <h3>Advanced Configuration</h3>
            <el-form :model="settings" label-width="200px">
              <el-form-item label="Log Level">
                <el-select v-model="settings.log_level" style="width: 200px">
                  <el-option label="Debug" value="debug" />
                  <el-option label="Info" value="info" />
                  <el-option label="Warning" value="warning" />
                  <el-option label="Error" value="error" />
                </el-select>
                <div class="form-help">Set the logging verbosity level</div>
              </el-form-item>

              <el-form-item label="Max Log Entries">
                <el-input-number
                  v-model="settings.max_log_entries"
                  :min="100"
                  :max="10000"
                  :step="100"
                  style="width: 200px"
                />
                <div class="form-help">Maximum number of log entries to keep</div>
              </el-form-item>

              <el-form-item label="Enable Debug Mode">
                <el-switch
                  v-model="settings.debug_mode"
                  active-text="Enabled"
                  inactive-text="Disabled"
                />
                <div class="form-help">Enable additional debugging features</div>
              </el-form-item>

              <el-form-item label="Developer Mode">
                <el-switch
                  v-model="settings.developer_mode"
                  active-text="Enabled"
                  inactive-text="Disabled"
                />
                <div class="form-help">Enable developer tools and features</div>
              </el-form-item>
            </el-form>
          </div>
        </el-tab-pane>
      </el-tabs>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useConnectionStore } from '@/stores/connection'
import { ElMessage, ElMessageBox } from 'element-plus'

const connectionStore = useConnectionStore()

const activeTab = ref('connection')
const saving = ref(false)

const defaultSettings = {
  server_url: 'http://127.0.0.1:8080',
  auto_connect: true,
  connection_timeout: 30,
  retry_attempts: 3,
  auto_refresh: true,
  refresh_interval: 30,
  refresh_on_focus: true,
  theme: 'dark',
  font_size: 14,
  compact_mode: false,
  notifications_enabled: true,
  notify_agent_connection: true,
  notify_task_completion: true,
  sound_effects: false,
  session_timeout: 120,
  require_auth: false,
  encrypt_local_data: true,
  clear_clipboard: true,
  log_level: 'info',
  max_log_entries: 1000,
  debug_mode: false,
  developer_mode: false
}

const settings = ref({ ...defaultSettings })

const loadSettings = async () => {
  try {
    const savedSettings = await connectionStore.loadSettings()
    if (savedSettings) {
      settings.value = { ...defaultSettings, ...savedSettings }
    }
  } catch (error) {
    console.error('Failed to load settings:', error)
  }
}

const saveSettings = async () => {
  try {
    saving.value = true

    await connectionStore.updateSettings(settings.value)
    ElMessage.success('Settings saved successfully')
  } catch (error) {
    ElMessage.error('Failed to save settings')
  } finally {
    saving.value = false
  }
}

const resetSettings = async () => {
  try {
    await ElMessageBox.confirm(
      'Are you sure you want to reset all settings to their default values? This action cannot be undone.',
      'Reset Settings',
      {
        confirmButtonText: 'Reset',
        cancelButtonText: 'Cancel',
        type: 'warning',
      }
    )

    settings.value = { ...defaultSettings }
    await saveSettings()
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to reset settings')
    }
  }
}

onMounted(() => {
  loadSettings()
})
</script>

<style scoped>
.settings-view {
  padding: 0;
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

.settings-content {
  background: var(--el-bg-color);
  border: 1px solid var(--el-border-color-light);
  border-radius: 8px;
  overflow: hidden;
}

.settings-section {
  padding: 20px;
}

.settings-section h3 {
  margin: 0 0 20px 0;
  color: var(--el-text-color-primary);
  font-size: 16px;
  font-weight: 600;
}

.form-help {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-top: 4px;
  line-height: 1.4;
}

.input-suffix {
  margin-left: 8px;
  color: var(--el-text-color-secondary);
  font-size: 14px;
}

:deep(.el-form-item__label) {
  color: var(--el-text-color-primary);
}

:deep(.el-tabs__header) {
  margin: 0;
}

:deep(.el-tabs__content) {
  padding: 0;
}

@media (max-width: 768px) {
  .header-content {
    flex-direction: column;
    gap: 12px;
    align-items: stretch;
  }

  .settings-section {
    padding: 16px;
  }

  :deep(.el-form-item__label) {
    width: 100% !important;
    text-align: left;
    margin-bottom: 8px;
  }

  :deep(.el-form-item__content) {
    margin-left: 0 !important;
  }
}
</style>
