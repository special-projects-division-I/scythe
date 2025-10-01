import winim/com

from strutils import strip


proc getAv*(): string =
  let wmisec = GetObject(r"winmgts:{impersonationLevel=impersonate}!\\.\root\SecurityCenter2")
  for avprod in wmisec.execQuery("SELECT displayName FROM AntiVirusProduct"):
    result.add(avprod.displayName.strip() & "\n")
  result = result.strip(trailing = true)
