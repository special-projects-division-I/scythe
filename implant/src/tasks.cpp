#include "tasks.h"

// Convert TaskType enum to string
std::string taskTypeToString(TaskType type) {
    switch (type) {
        case TaskType::SHELL:
            return "shell";
        case TaskType::POWERSHELL:
            return "powershell";
        case TaskType::DOWNLOAD:
            return "download";
        case TaskType::UPLOAD:
            return "upload";
        case TaskType::SCREENSHOT:
            return "screenshot";
        case TaskType::KEYLOG:
            return "keylog";
        case TaskType::PROCESS_LIST:
            return "process_list";
        case TaskType::SYSTEM_INFO:
            return "system_info";
        case TaskType::NETWORK_INFO:
            return "network_info";
        case TaskType::FILE_LIST:
            return "file_list";
        case TaskType::REGISTRY:
            return "registry";
        case TaskType::SLEEP:
            return "sleep";
        case TaskType::JITTER:
            return "jitter";
        case TaskType::EXIT:
            return "exit";
        default:
            return "unknown";
    }
}

// Convert string to TaskType enum
TaskType stringToTaskType(const std::string& str) {
    if (str == "shell") return TaskType::SHELL;
    if (str == "powershell") return TaskType::POWERSHELL;
    if (str == "download") return TaskType::DOWNLOAD;
    if (str == "upload") return TaskType::UPLOAD;
    if (str == "screenshot") return TaskType::SCREENSHOT;
    if (str == "keylog") return TaskType::KEYLOG;
    if (str == "process_list") return TaskType::PROCESS_LIST;
    if (str == "system_info") return TaskType::SYSTEM_INFO;
    if (str == "network_info") return TaskType::NETWORK_INFO;
    if (str == "file_list") return TaskType::FILE_LIST;
    if (str == "registry") return TaskType::REGISTRY;
    if (str == "sleep") return TaskType::SLEEP;
    if (str == "jitter") return TaskType::JITTER;
    if (str == "exit") return TaskType::EXIT;
    return TaskType::SHELL; // default fallback
}

// Convert TaskStatus enum to string
std::string taskStatusToString(TaskStatus status) {
    switch (status) {
        case TaskStatus::PENDING:
            return "pending";
        case TaskStatus::ASSIGNED:
            return "assigned";
        case TaskStatus::RUNNING:
            return "running";
        case TaskStatus::COMPLETED:
            return "completed";
        case TaskStatus::FAILED:
            return "failed";
        case TaskStatus::TIMEOUT:
            return "timeout";
        default:
            return "unknown";
    }
}

// Convert string to TaskStatus enum
TaskStatus stringToTaskStatus(const std::string& str) {
    if (str == "pending") return TaskStatus::PENDING;
    if (str == "assigned") return TaskStatus::ASSIGNED;
    if (str == "running") return TaskStatus::RUNNING;
    if (str == "completed") return TaskStatus::COMPLETED;
    if (str == "failed") return TaskStatus::FAILED;
    if (str == "timeout") return TaskStatus::TIMEOUT;
    return TaskStatus::PENDING; // default fallback
}

// Convert TaskPriority enum to string
std::string taskPriorityToString(TaskPriority priority) {
    switch (priority) {
        case TaskPriority::LOW:
            return "low";
        case TaskPriority::NORMAL:
            return "normal";
        case TaskPriority::HIGH:
            return "high";
        case TaskPriority::CRITICAL:
            return "critical";
        default:
            return "normal";
    }
}

// Convert string to TaskPriority enum
TaskPriority stringToTaskPriority(const std::string& str) {
    if (str == "low") return TaskPriority::LOW;
    if (str == "normal") return TaskPriority::NORMAL;
    if (str == "high") return TaskPriority::HIGH;
    if (str == "critical") return TaskPriority::CRITICAL;
    return TaskPriority::NORMAL; // default fallback
}