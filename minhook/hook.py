import os
import ctypes
import platform
from ctypes import wintypes
__all__ = [
    "HookException",
    "Hook",
]
bits, linkage = platform.architecture()
if linkage != 'WindowsPE':
    raise RuntimeError('minhook only support windows')
if bits == '64bit':
    dllname = 'MinHook.x64.dll'
elif bits == '32bit':
    dllname = 'MinHook.x86.dll'
else:
    raise RuntimeError('minhook only support 64bit or 32bit')
minhook = ctypes.windll.LoadLibrary(
    os.path.join(os.path.dirname(__file__), dllname))

MH_Initialize = minhook.MH_Initialize

MH_CreateHook = minhook.MH_CreateHook
MH_CreateHook.argtypes = (
    wintypes.LPVOID,
    wintypes.LPVOID,
    ctypes.POINTER(wintypes.LPVOID),
)

MH_CreateHookApi = minhook.MH_CreateHookApi
MH_CreateHookApi.argtypes = (
    wintypes.LPCWSTR,
    wintypes.LPCSTR,
    wintypes.LPVOID,
    ctypes.POINTER(wintypes.LPVOID),
)

MH_CreateHookApiEx = minhook.MH_CreateHookApiEx
MH_CreateHookApiEx.argtypes = (
    wintypes.LPCWSTR,
    wintypes.LPCSTR,
    wintypes.LPVOID,
    ctypes.POINTER(wintypes.LPVOID),
    ctypes.POINTER(wintypes.LPVOID),
)

MH_EnableHook = minhook.MH_EnableHook
MH_EnableHook.argtypes = (wintypes.LPVOID,)

MH_DisableHook = minhook.MH_DisableHook
MH_DisableHook.argtypes = (wintypes.LPVOID,)

MH_RemoveHook = minhook.MH_RemoveHook
MH_RemoveHook.argtypes = (wintypes.LPVOID,)

MH_Uninitialize = minhook.MH_Uninitialize

MH_StatusToString = minhook.MH_StatusToString
MH_StatusToString.restype = ctypes.c_char_p
MH_StatusToString.argtypes = (ctypes.c_long,)

MH_OK = 0

GetModuleHandleW = ctypes.windll.kernel32.GetModuleHandleW
GetModuleHandleW.restype = wintypes.LPVOID
GetModuleHandleW.argtypes = (wintypes.LPCWSTR,)

GetProcAddress = ctypes.windll.kernel32.GetProcAddress
GetProcAddress.restype = ctypes.c_void_p
GetProcAddress.argtypes = (wintypes.LPVOID, wintypes.LPCSTR)


class HookException(Exception):
    pass


class Hook:
    '''
        需要继承后指定属性并实现detour方法，例如对于GetModuleHandleW
        ```py
        class TestHook(Hook):
            prototype = ctypes.WINFUNCTYPE(wintypes.HANDLE, wintypes.LPCWSTR)
            modname = 'kernel32'
            apiname = 'GetModuleHandleW'
            def detour(self, lpModuleName):
                print('hook param', lpModuleName)
                ret = self.fp_orginal(lpModuleName)
                print('hook ret = %08X' % ret)
                return ret
        ```
    '''
    # hook后的原函数(Trampoline)，用于在detour中调用
    fp_orginal = None
    # hook的函数地址，用于开关
    fp_target = None

    prototype = None
    modname: str = None
    apiname: str = None

    def __init__(self):
        if self.prototype is None:
            raise NotImplementedError('prototype not set')
        if self.modname is None:
            raise NotImplementedError('modname not set')
        if self.apiname is None:
            raise NotImplementedError('apiname not set')
        ret = MH_Initialize()
        if ret != MH_OK:
            raise HookException(MH_StatusToString(ret))
        self.fp_detour = self.prototype(self.detour)
        _fp_orginal = wintypes.LPVOID()
        _fp_target = wintypes.LPVOID(self.get_hook_address())
        ret = MH_CreateHook(
            _fp_target,
            ctypes.cast(self.fp_detour, wintypes.LPVOID),
            ctypes.byref(_fp_orginal),
        )

        if ret != MH_OK:
            raise HookException(MH_StatusToString(ret))
        ret = MH_EnableHook(self.fp_target)
        if ret != MH_OK:
            raise HookException(MH_StatusToString(ret))
        self.fp_orginal = self.prototype(_fp_orginal.value)
        self.fp_target = self.prototype(_fp_target.value)

    def get_hook_address(self) -> int:
        mod = GetModuleHandleW(self.modname)
        if not mod:
            raise HookException('modname {} not found'.format(self.modname))
        address = GetProcAddress(
            mod,
            ctypes.c_char_p(self.apiname.encode('ascii')),
        )
        if not address:
            raise HookException('apiname {} not found'.format(self.apiname))
        return address

    def disable(self):
        ret = MH_DisableHook(ctypes.cast(self.fp_target, wintypes.LPVOID))
        if ret != MH_OK:
            raise HookException(MH_StatusToString(ret))

    def enable(self):
        ret = MH_EnableHook(ctypes.cast(self.fp_target, wintypes.LPVOID))
        if ret != MH_OK:
            raise HookException(MH_StatusToString(ret))
    def remove(self):
        ret = MH_RemoveHook(ctypes.cast(self.fp_target, wintypes.LPVOID))
        if ret != MH_OK:
            raise HookException(MH_StatusToString(ret))

    def detour(self, *args, **kwargs):
        raise NotImplementedError('detour not implemented')
    def __del__(self):
        self.remove()

