import { createRouter, createWebHistory } from "vue-router";
import type { RouteRecordRaw } from "vue-router";
import Dashboard from "@/views/Dashboard.vue";
import Agents from "@/views/Agents.vue";
import Tasks from "@/views/Tasks.vue";
import Files from "@/views/Files.vue";
import Logs from "@/views/Logs.vue";
import Settings from "@/views/Settings.vue";

const routes: RouteRecordRaw[] = [
  {
    path: "/",
    redirect: "/dashboard",
  },
  {
    path: "/dashboard",
    name: "Dashboard",
    component: Dashboard,
    meta: {
      title: "Dashboard - SCYTHE C2 Controller",
      requiresConnection: false,
    },
  },
  {
    path: "/agents",
    name: "Agents",
    component: Agents,
    meta: {
      title: "Agents - SCYTHE C2 Controller",
      requiresConnection: true,
    },
  },
  {
    path: "/agents/:id",
    name: "AgentDetails",
    component: (): Promise<typeof import("@/views/AgentDetails.vue").default> =>
      import("@/views/AgentDetails.vue"),
    meta: {
      title: "Agent Details - SCYTHE C2 Controller",
      requiresConnection: true,
    },
  },
  {
    path: "/tasks",
    name: "Tasks",
    component: Tasks,
    meta: {
      title: "Tasks - SCYTHE C2 Controller",
      requiresConnection: true,
    },
  },
  {
    path: "/files",
    name: "Files",
    component: Files,
    meta: {
      title: "File Manager - SCYTHE C2 Controller",
      requiresConnection: true,
    },
  },
  {
    path: "/logs",
    name: "Logs",
    component: Logs,
    meta: {
      title: "Activity Logs - SCYTHE C2 Controller",
      requiresConnection: true,
    },
  },
  {
    path: "/settings",
    name: "Settings",
    component: Settings,
    meta: {
      title: "Settings - SCYTHE C2 Controller",
      requiresConnection: false,
    },
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

// Navigation guards
router.beforeEach(async (to, _from, next) => {
  // Set document title
  if (to.meta.title) {
    document.title = to.meta.title as string;
  }

  // Check connection requirement
  if (to.meta.requiresConnection) {
    // Dynamically import to avoid circular dependency
    const { useConnectionStore } = await import("@/stores/connection");
    const connectionStore = useConnectionStore();

    if (!connectionStore.isConnected) {
      // Redirect to dashboard with a message
      next("/dashboard");
      return;
    }
  }

  next();
});

export default router;
