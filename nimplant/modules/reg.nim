import registry

from strutils import join, split, startsWith


proc reg*(args: varargs[string]): string =
  var
    command: string
    path: string
    key: string
    value: string
    handleStr: string
    regpath: string
    handle: registry.HKEY

  case args.len:
    of 2:
      command = args[0]
      path = args[1]
    of 3:
      command = args[0]
      path = args[1]
      key = args[2]
    of 4:
      command = args[0]
      path = args[1]
      key = args[2]
      value = args[3]
    else:
      result = "Invalid number of arguments received. Usage: reg <command> <path> [<key> [<value>]]"

  try:
    handleStr = path.split("\\")[0]
    regPath = path.split("\\", 1)[1]

  except:
    result = "Unable to parse registry path."
    return

  if handleStr.startsWith("HKCU"):
    handle = registry.HKEY_CURRENT_USER
  elif handleStr.startswith("HKLM"):
    handle = registry.HKEY_LOCAL_MACHINE
  else:
    result = "Invalid registry. Only HKCU and HKLM are supported."
    return
  try:
    if command == "query":
      result = getUnicodeValue(regPath, key, handle)
    elif command == "add":
      setUnicodeValue(regPath, key, value, handle)
      result = "Registry value set successfully"
    else:
      result = "Unknown reg command. Usage: reg <command> <path> [<key> [<value>]]"
  except:
    result = "Registry operation failed: " & getCurrentExceptionMsg()
