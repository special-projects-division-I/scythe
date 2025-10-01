from os import copyDir, copyFile, dirExists, splitPath, `/`, extractFilename
from strutils import join


proc copyFileToDir(source, destDir: string) =
  let filename = extractFilename(source)
  let destPath = destDir / filename
  copyFile(source, destPath)

proc copyX*(args: varargs[string]): string =

  var
      source: string
      destination: string
  if args.len >= 2:
      source = args[0]
      destination = args[1 .. ^1].join(" ")

  else:
      result = "Invalid number of arguments received. Usage: 'cp [src] [dst]'"
      return result

  try:
    if dirExists(source):
      if dirExists(destination):
          copyDir(source, destination)
      else:
          result = "Cannot copy directory to file"
          return result
    elif dirExists(destination):
      copyFileToDir(source, destination)
    else:
      copyFile(source, destination)
    result = "Copied '" & source & "' to '" & destination & "'."
  except:
    result = "Copy failed: " & getCurrentExceptionMsg()
