from winim/lean import GetUserName, LPWSTR, DWORD, TCHAR
from winim/utils import `&`

proc whoami*(): string =
  var
    buf: array[257, TCHAR]
    lpBuffer: LPWSTR = addr(buf[0])
    pcBuff: DWORD = int32(len(buf))
  discard GetUserName(lpBuffer, &pcBuff)

  for character in buf:
    if character == 0:
      break
    result.add(char(character))
