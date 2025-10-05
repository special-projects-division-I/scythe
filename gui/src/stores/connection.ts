import { defineStore } from "pinia";
import { ref, computed } from "vue";
import { invoke } from "@tauri-apps/api/tauri";
// import { ElMessage } from "element-plus";

interface ServerConnection {
  url: string;
  is_connected: boolean;
  last_connected?: string;
  auth_token?: string;
}

interface GuiSettings {
  server_url: string;
  auto_connect: boolean;
  auto_refresh: boolean;
  refresh_interval: number;
  theme: string;
  log_level: string;
}

export const useConnectionStore = defineStore("connection", () => {
  // State
  const serverUrl = ref("http://127.0.0.1:8080");
  const isConnected = ref(false);
  const status = ref<"disconnected" | "connecting" | "connected">(
    "disconnected",
  );
  const authToken = ref<string | null>(null);
  const lastConnected = ref<Date | null>(null);
  const autoConnect = ref(true);
  const autoRefresh = ref(true);
  const refreshInterval = ref(30);
  const theme = ref("dark");
  const logLevel = ref("info");

  // Getters
  const connectionInfo = computed(() => ({
    url: serverUrl.value,
    is_connected: isConnected.value,
    last_connected: lastConnected.value?.toISOString(),
    auth_token: authToken.value || undefined,
  }));

  const settings = computed<GuiSettings>(() => ({
    server_url: serverUrl.value,
    auto_connect: autoConnect.value,
    auto_refresh: autoRefresh.value,
    refresh_interval: refreshInterval.value,
    theme: theme.value,
    log_level: logLevel.value,
  }));

  // Actions
  const connect = async (
    url?: string,
    username?: string,
    password?: string,
  ): Promise<boolean> => {
    try {
      status.value = "connecting";

      const targetUrl = url || serverUrl.value;

      const connection: ServerConnection = await invoke("connect_to_server", {
        url: targetUrl,
        username,
        password,
      });

      if (connection.is_connected) {
        serverUrl.value = connection.url;
        isConnected.value = true;
        status.value = "connected";
        authToken.value = connection.auth_token || null;
        lastConnected.value = connection.last_connected
          ? new Date(connection.last_connected)
          : new Date();

        // Save settings
        await saveSettings();

        return true;
      } else {
        throw new Error("Connection failed");
      }
    } catch (error) {
      status.value = "disconnected";
      isConnected.value = false;
      authToken.value = null;
      throw error;
    }
  };

  const disconnect = async (): Promise<boolean> => {
    try {
      await invoke("disconnect_from_server");

      isConnected.value = false;
      status.value = "disconnected";
      authToken.value = null;

      return true;
    } catch (error) {
      throw error;
    }
  };

  const testConnection = async (_url?: string): Promise<boolean> => {
    try {
      // const targetUrl = url || serverUrl.value;
      const connection: ServerConnection = await invoke("get_server_status");
      return connection.is_connected;
    } catch (error) {
      return false;
    }
  };

  const loadSettings = async (): Promise<GuiSettings | null> => {
    try {
      const settings: GuiSettings = await invoke("load_settings");

      serverUrl.value = settings.server_url;
      autoConnect.value = settings.auto_connect;
      autoRefresh.value = settings.auto_refresh;
      refreshInterval.value = settings.refresh_interval;
      theme.value = settings.theme;
      logLevel.value = settings.log_level;

      return settings;
    } catch (error) {
      console.warn("Failed to load settings:", error);
      return null;
    }
  };

  const saveSettings = async (): Promise<boolean> => {
    try {
      await invoke("save_settings", {
        settings: settings.value,
      });
      return true;
    } catch (error) {
      console.error("Failed to save settings:", error);
      return false;
    }
  };

  const updateSettings = async (
    newSettings: Partial<GuiSettings>,
  ): Promise<void> => {
    if (newSettings.server_url !== undefined) {
      serverUrl.value = newSettings.server_url;
    }
    if (newSettings.auto_connect !== undefined) {
      autoConnect.value = newSettings.auto_connect;
    }
    if (newSettings.auto_refresh !== undefined) {
      autoRefresh.value = newSettings.auto_refresh;
    }
    if (newSettings.refresh_interval !== undefined) {
      refreshInterval.value = newSettings.refresh_interval;
    }
    if (newSettings.theme !== undefined) {
      theme.value = newSettings.theme;
    }
    if (newSettings.log_level !== undefined) {
      logLevel.value = newSettings.log_level;
    }

    await saveSettings();
  };

  const refreshStatus = async (): Promise<ServerConnection> => {
    try {
      const connection: ServerConnection = await invoke("get_server_status");

      if (connection.is_connected !== isConnected.value) {
        isConnected.value = connection.is_connected;
        status.value = connection.is_connected ? "connected" : "disconnected";
      }

      if (connection.auth_token && connection.auth_token !== authToken.value) {
        authToken.value = connection.auth_token;
      }

      return connection;
    } catch (error) {
      isConnected.value = false;
      status.value = "disconnected";
      authToken.value = null;
      throw error;
    }
  };

  // Auto-connect on store initialization
  const initialize = async (): Promise<void> => {
    await loadSettings();

    if (autoConnect.value) {
      try {
        await connect();
      } catch (error) {
        console.warn("Auto-connect failed:", error);
      }
    }
  };

  return {
    // State
    serverUrl,
    isConnected,
    status,
    authToken,
    lastConnected,
    autoConnect,
    autoRefresh,
    refreshInterval,
    theme,
    logLevel,

    // Getters
    connectionInfo,
    settings,

    // Actions
    connect,
    disconnect,
    testConnection,
    loadSettings,
    saveSettings,
    updateSettings,
    refreshStatus,
    initialize,
  };
});
