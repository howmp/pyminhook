# pyminhook

此库是对[minhook](https://github.com/TsudaKageyu/minhook/)的python包装，仅支持windows。

## 安装

`pip install pyminhook`

## 用法如下

```py
import ctypes 
from ctypes import wintypes
from minhook import *
if __name__ == "__main__":

    class TestHook(Hook):
        prototype = ctypes.WINFUNCTYPE(wintypes.HANDLE, wintypes.LPCWSTR)
        modname = 'kernel32'
        apiname = 'GetModuleHandleW'

        def detour(self, lpModuleName):
            print('before hook param', lpModuleName)
            ret = self.fp_orginal(lpModuleName)
            print('after hook ret = %08X' % ret)
            return ret

    h = TestHook()
    print('-' * 32)
    print('call 1 ret = %08X' % h.fp_target('kernel32'))
    print('-' * 32)
    h.disable()
    print('call 2 ret = %08X' % h.fp_target('ntdll'))
    print('-' * 32)
    h.enable()
    print('call 3 ret = %08X' % h.fp_target('user32'))
```

## 输出如下:

```txt
--------------------------------
before hook param kernel32
after hook ret = 7FF970430000
call 1 ret = 7FF970430000
--------------------------------
call 2 ret = 7FF9718E0000
--------------------------------
before hook param user32
after hook ret = 7FF970120000
call 3 ret = 7FF970120000
```
