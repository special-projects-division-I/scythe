import { defineStore } from "pinia";
import { ref, computed } from "vue";
import { invoke } from "@tauri-apps/api/tauri";
// import { ElMessage } from "element-plus";

interface Agent {
  id: string;
  hostname: string;
  username: string;
  domain: string;
  os: string;
  arch: string;
  process_id: number;
  process_name: string;
  integrity_level: string;
  remote_ip: string;
  internal_ip: string;
  last_seen: string;
  first_seen: string;
  sleep_interval: number;
  jitter: number;
  is_active: boolean;
  encryption_key: string;
}

interface Task {
  id: string;
  agent_id: string;
  command: string;
  arguments: string[];
  task_type: string;
  created_at: string;
  assigned_at?: string;
  status: string;
  priority: string;
  timeout?: number;
}

interface TaskResult {
  id: string;
  task_id: string;
  agent_id: string;
  output: string;
  error?: string;
  exit_code?: number;
  execution_time: number;
  completed_at: string;
  file_data?: number[];
}

export const useAgentsStore = defineStore("agents", () => {
  // State
  const agents = ref<Agent[]>([]);
  const selectedAgentId = ref<string | null>(null);
  const loading = ref(false);
  const error = ref<string | null>(null);
  const lastRefresh = ref<Date | null>(null);

  // Tasks and results for selected agent
  const agentTasks = ref<Task[]>([]);
  const agentResults = ref<TaskResult[]>([]);
  const tasksLoading = ref(false);
  const resultsLoading = ref(false);

  // Getters
  const selectedAgent = computed(() => {
    if (!selectedAgentId.value) {
      return null;
    }
    return (
      agents.value.find((agent) => agent.id === selectedAgentId.value) || null
    );
  });

  const activeAgents = computed(() => {
    return agents.value.filter((agent) => agent.is_active);
  });

  const inactiveAgents = computed(() => {
    return agents.value.filter((agent) => !agent.is_active);
  });

  const agentsByOS = computed(() => {
    const grouped: Record<string, Agent[]> = {};
    agents.value.forEach((agent) => {
      const os = agent.os.split(" ")[0]; // Get first part of OS name
      if (!grouped[os]) {
        grouped[os] = [];
      }
      grouped[os].push(agent);
    });
    return grouped;
  });

  const agentStats = computed(() => {
    const total = agents.value.length;
    const active = activeAgents.value.length;
    const windows = agents.value.filter((a) =>
      a.os.toLowerCase().includes("windows"),
    ).length;
    const linux = agents.value.filter((a) =>
      a.os.toLowerCase().includes("linux"),
    ).length;
    const mac = agents.value.filter((a) =>
      a.os.toLowerCase().includes("mac"),
    ).length;

    return {
      total,
      active,
      inactive: total - active,
      windows,
      linux,
      mac,
      other: total - windows - linux - mac,
    };
  });

  // Actions
  const fetchAgents = async () => {
    try {
      loading.value = true;
      error.value = null;

      const fetchedAgents: Agent[] = await invoke("get_agents");
      agents.value = fetchedAgents;
      lastRefresh.value = new Date();

      return fetchedAgents;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      error.value = `Failed to fetch agents: ${errorMessage}`;
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const getAgentDetails = async (agentId: string) => {
    try {
      const agent: Agent = await invoke("get_agent_details", { agentId });

      // Update agent in the list
      const index = agents.value.findIndex((a) => a.id === agentId);
      if (index !== -1) {
        agents.value[index] = agent;
      }

      return agent;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      error.value = `Failed to get agent details: ${errorMessage}`;
      throw err;
    }
  };

  const updateAgent = async (agentId: string, updates: Partial<Agent>) => {
    try {
      const currentAgent = agents.value.find((a) => a.id === agentId);
      if (!currentAgent) {
        throw new Error("Agent not found");
      }

      const updatedAgent = { ...currentAgent, ...updates };
      await invoke("update_agent", { agentId, agent: updatedAgent });

      // Update local state
      const index = agents.value.findIndex((a) => a.id === agentId);
      if (index !== -1) {
        agents.value[index] = updatedAgent;
      }

      return updatedAgent;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      error.value = `Failed to update agent: ${errorMessage}`;
      throw err;
    }
  };

  const deleteAgent = async (agentId: string) => {
    try {
      await invoke("delete_agent", { agentId });

      // Remove from local state
      agents.value = agents.value.filter((a) => a.id !== agentId);

      // Clear selection if this agent was selected
      if (selectedAgentId.value === agentId) {
        selectedAgentId.value = null;
        agentTasks.value = [];
        agentResults.value = [];
      }

      return true;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      error.value = `Failed to delete agent: ${errorMessage}`;
      throw err;
    }
  };

  const selectAgent = (agentId: string | null) => {
    selectedAgentId.value = agentId;

    // Clear tasks and results when changing selection
    agentTasks.value = [];
    agentResults.value = [];

    // Load tasks and results for the selected agent
    if (agentId) {
      void fetchAgentTasks(agentId);
      void fetchAgentResults(agentId);
    }
  };

  const fetchAgentTasks = async (agentId: string) => {
    try {
      tasksLoading.value = true;
      const tasks: Task[] = await invoke("get_agent_tasks", { agentId });
      agentTasks.value = tasks;
      return tasks;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      error.value = `Failed to fetch agent tasks: ${errorMessage}`;
      throw err;
    } finally {
      tasksLoading.value = false;
    }
  };

  const fetchAgentResults = async (agentId: string) => {
    try {
      resultsLoading.value = true;
      const results: TaskResult[] = await invoke("get_task_results", {
        agentId,
      });
      agentResults.value = results;
      return results;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      error.value = `Failed to fetch agent results: ${errorMessage}`;
      throw err;
    } finally {
      resultsLoading.value = false;
    }
  };

  const createTask = async (
    agentId: string,
    command: string,
    taskArguments: string[],
    taskType: string,
  ) => {
    try {
      const task: Task = await invoke("create_task", {
        agentId,
        command,
        arguments: taskArguments,
        taskType,
      });

      // Add to local tasks if it's for the selected agent
      if (selectedAgentId.value === agentId) {
        agentTasks.value.unshift(task);
      }

      return task;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      error.value = `Failed to create task: ${errorMessage}`;
      throw err;
    }
  };

  const refreshAgent = async (agentId: string) => {
    try {
      await getAgentDetails(agentId);

      if (selectedAgentId.value === agentId) {
        await fetchAgentTasks(agentId);
        await fetchAgentResults(agentId);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      error.value = `Failed to refresh agent: ${errorMessage}`;
      throw err;
    }
  };

  const refreshAll = async () => {
    await fetchAgents();

    if (selectedAgentId.value) {
      await fetchAgentTasks(selectedAgentId.value);
      await fetchAgentResults(selectedAgentId.value);
    }
  };

  const clearError = () => {
    error.value = null;
  };

  // Utility functions
  const getAgentStatus = (agent: Agent): string => {
    if (!agent.is_active) {
      return "Inactive";
    }

    const now = new Date();
    const lastSeen = new Date(agent.last_seen);
    const diffMinutes = (now.getTime() - lastSeen.getTime()) / (1000 * 60);

    if (diffMinutes < 1) {
      return "Active";
    }
    if (diffMinutes < 5) {
      return "Idle";
    }
    return "Stale";
  };

  const getAgentUptime = (agent: Agent): string => {
    const firstSeen = new Date(agent.first_seen);
    const now = new Date();
    const diffMs = now.getTime() - firstSeen.getTime();

    const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    const hours = Math.floor(
      (diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60),
    );
    const minutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));

    if (days > 0) {
      return `${days}d ${hours}h`;
    }
    if (hours > 0) {
      return `${hours}h ${minutes}m`;
    }
    return `${minutes}m`;
  };

  return {
    // State
    agents,
    selectedAgentId,
    loading,
    error,
    lastRefresh,
    agentTasks,
    agentResults,
    tasksLoading,
    resultsLoading,

    // Getters
    selectedAgent,
    activeAgents,
    inactiveAgents,
    agentsByOS,
    agentStats,

    // Actions
    fetchAgents,
    getAgentDetails,
    updateAgent,
    deleteAgent,
    selectAgent,
    fetchAgentTasks,
    fetchAgentResults,
    createTask,
    refreshAgent,
    refreshAll,
    clearError,

    // Utilities
    getAgentStatus,
    getAgentUptime,
  };
});
