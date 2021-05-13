using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading;
using System.Globalization;
using System.ComponentModel;

namespace RobloxBasic.Memory
{
    public class Mem
    {
        #region DllImports
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(
            UInt32 dwDesiredAccess,
            bool bInheritHandle,
            Int32 dwProcessId
            );

#if WINXP
#else
        [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
        public static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION32 lpBuffer, UIntPtr dwLength);

        [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
        public static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION64 lpBuffer, UIntPtr dwLength);

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        public UIntPtr VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer)
        {
            UIntPtr retVal;

            // TODO: Need to change this to only check once.
            if (Is64Bit || IntPtr.Size == 8)
            {
                // 64 bit
                MEMORY_BASIC_INFORMATION64 tmp64 = new MEMORY_BASIC_INFORMATION64();
                retVal = Native_VirtualQueryEx(hProcess, lpAddress, out tmp64, new UIntPtr((uint)Marshal.SizeOf(tmp64)));

                lpBuffer.BaseAddress = tmp64.BaseAddress;
                lpBuffer.AllocationBase = tmp64.AllocationBase;
                lpBuffer.AllocationProtect = tmp64.AllocationProtect;
                lpBuffer.RegionSize = (long)tmp64.RegionSize;
                lpBuffer.State = tmp64.State;
                lpBuffer.Protect = tmp64.Protect;
                lpBuffer.Type = tmp64.Type;

                return retVal;
            }

            MEMORY_BASIC_INFORMATION32 tmp32 = new MEMORY_BASIC_INFORMATION32();

            retVal = Native_VirtualQueryEx(hProcess, lpAddress, out tmp32, new UIntPtr((uint)Marshal.SizeOf(tmp32)));

            lpBuffer.BaseAddress = tmp32.BaseAddress;
            lpBuffer.AllocationBase = tmp32.AllocationBase;
            lpBuffer.AllocationProtect = tmp32.AllocationProtect;
            lpBuffer.RegionSize = tmp32.RegionSize;
            lpBuffer.State = tmp32.State;
            lpBuffer.Protect = tmp32.Protect;
            lpBuffer.Type = tmp32.Type;

            return retVal;
        }

        [DllImport("kernel32.dll")]
        static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);
#endif

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32.dll")]
        static extern uint SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        static extern int ResumeThread(IntPtr hThread);

        [DllImport("dbghelp.dll")]
        static extern bool MiniDumpWriteDump(
            IntPtr hProcess,
            Int32 ProcessId,
            IntPtr hFile,
            MINIDUMP_TYPE DumpType,
            IntPtr ExceptionParam,
            IntPtr UserStreamParam,
            IntPtr CallackParam);

        [DllImport("user32.dll", SetLastError = true)]
        static extern int GetWindowLong(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr w, IntPtr l);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            UIntPtr lpBaseAddress,
            string lpBuffer,
            UIntPtr nSize,
            out IntPtr lpNumberOfBytesWritten
        );

        [DllImport("kernel32.dll")]
        static extern int GetProcessId(IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern uint GetPrivateProfileString(
           string lpAppName,
           string lpKeyName,
           string lpDefault,
           StringBuilder lpReturnedString,
           uint nSize,
           string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool VirtualFreeEx(
            IntPtr hProcess,
            UIntPtr lpAddress,
            UIntPtr dwSize,
            uint dwFreeType
            );

        [DllImport("psapi.dll")]
        static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In][MarshalAs(UnmanagedType.U4)] int nSize);
        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool EnumProcessModules(IntPtr hProcess,
        [Out] IntPtr lphModule,
        uint cb,
        [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, out ulong lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] IntPtr lpBuffer, UIntPtr nSize, out ulong lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern UIntPtr VirtualAllocEx(
            IntPtr hProcess,
            UIntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect
        );

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, UIntPtr lpAddress,
            IntPtr dwSize, MemoryProtection flNewProtect, out MemoryProtection lpflOldProtect);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
        public static extern UIntPtr GetProcAddress(
            IntPtr hModule,
            string procName
        );

        [DllImport("kernel32.dll", EntryPoint = "CloseHandle")]
        private static extern bool _CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern Int32 CloseHandle(
        IntPtr hObject
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(
            string lpModuleName
        );

        [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
        internal static extern Int32 WaitForSingleObject(
            IntPtr handle,
            Int32 milliseconds
        );

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesWritten);

        // Added to avoid casting to UIntPtr
        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32")]
        public static extern IntPtr CreateRemoteThread(
          IntPtr hProcess,
          IntPtr lpThreadAttributes,
          uint dwStackSize,
          UIntPtr lpStartAddress, // raw Pointer into remote process  
          UIntPtr lpParameter,
          uint dwCreationFlags,
          out IntPtr lpThreadId
        );

        [DllImport("kernel32")]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool lpSystemInfo);

        [DllImport("user32.dll")]
        static extern bool SetForegroundWindow(IntPtr hWnd);

        private enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = 0x0000001F,
            NoHeaps = 0x40000000
        }
        //inner struct used only internally
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct PROCESSENTRY32
        {
            const int MAX_PATH = 260;
            internal UInt32 dwSize;
            internal UInt32 cntUsage;
            internal UInt32 th32ProcessID;
            internal IntPtr th32DefaultHeapID;
            internal UInt32 th32ModuleID;
            internal UInt32 cntThreads;
            internal UInt32 th32ParentProcessID;
            internal Int32 pcPriClassBase;
            internal UInt32 dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            internal string szExeFile;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        public struct MODULEENTRY32
        {
            internal uint dwSize;
            internal uint th32ModuleID;
            internal uint th32ProcessID;
            internal uint GlblcntUsage;
            internal uint ProccntUsage;
            internal IntPtr modBaseAddr;
            internal uint modBaseSize;
            internal IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            internal string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            internal string szExePath;
        }

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern IntPtr CreateToolhelp32Snapshot([In] UInt32 dwFlags, [In] UInt32 th32ProcessID);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern bool Process32First([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32.dll")]
        static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);
        [DllImport("kernel32.dll")]
        static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern bool Process32Next([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        // privileges
        const int PROCESS_CREATE_THREAD = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_READ = 0x0010;

        // used for memory allocation
        const uint MEM_FREE = 0x10000;
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;

        private const uint PAGE_READONLY = 0x02;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_WRITECOPY = 0x08;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        private const uint PAGE_EXECUTE = 0x10;
        private const uint PAGE_EXECUTE_READ = 0x20;

        private const uint PAGE_GUARD = 0x100;
        private const uint PAGE_NOACCESS = 0x01;

        private uint MEM_PRIVATE = 0x20000;
        private uint MEM_IMAGE = 0x1000000;

        #endregion

        public IntPtr pHandle;
        Dictionary<string, CancellationTokenSource> FreezeTokenSrcs = new Dictionary<string, CancellationTokenSource>();
        public Process theProc = null;

        internal enum MINIDUMP_TYPE
        {
            MiniDumpNormal = 0x00000000,
            MiniDumpWithDataSegs = 0x00000001,
            MiniDumpWithFullMemory = 0x00000002,
            MiniDumpWithHandleData = 0x00000004,
            MiniDumpFilterMemory = 0x00000008,
            MiniDumpScanMemory = 0x00000010,
            MiniDumpWithUnloadedModules = 0x00000020,
            MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
            MiniDumpFilterModulePaths = 0x00000080,
            MiniDumpWithProcessThreadData = 0x00000100,
            MiniDumpWithPrivateReadWriteMemory = 0x00000200,
            MiniDumpWithoutOptionalData = 0x00000400,
            MiniDumpWithFullMemoryInfo = 0x00000800,
            MiniDumpWithThreadInfo = 0x00001000,
            MiniDumpWithCodeSegs = 0x00002000
        }

        public bool OpenProcess(int pid)
        {
            if (pid <= 0)
            {
                Debug.WriteLine("ERROR: OpenProcess given proc ID 0.");
                return false;
            }
            if (theProc != null && theProc.Id == pid)
                return true;
            try
            {
                theProc = Process.GetProcessById(pid);
                if (theProc != null && !theProc.Responding)
                {
                    Debug.WriteLine("ERROR: OpenProcess: Process is not responding or null.");
                    return false;
                }
                pHandle = OpenProcess(0x1F0FFF, true, pid);
                try
                {
                    Process.EnterDebugMode();
                }
                catch (Win32Exception) { }
                if (pHandle == IntPtr.Zero)
                {
                    var eCode = Marshal.GetLastWin32Error();
                    Debug.WriteLine("ERROR: OpenProcess has failed opening a handle to the target process (GetLastWin32ErrorCode: " + eCode + ")");
                    Process.LeaveDebugMode();
                    theProc = null;
                    return false;
                }
                Is64Bit = Environment.Is64BitOperatingSystem && (IsWow64Process(pHandle, out bool retVal) && !retVal);
                mainModule = theProc.MainModule;
                GetModules();
                Debug.WriteLine("Process #" + theProc + " is now open.");
                return true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("ERROR: OpenProcess has crashed. " + ex);
                return false;
            }
        }

        public bool OpenProcess(string proc)
        {
            return OpenProcess(GetProcIdFromName(proc));
        }

        public bool OpenRoblox()
        {
            return OpenProcess(GetProcIdFromName("RobloxPlayerBeta.exe"));
        }

        public bool OpenMinecraft()
        {
            return OpenProcess(GetProcIdFromName("Minecraft.Windows.exe"));
        }

        private bool _is64Bit;
        public bool Is64Bit
        {
            get { return _is64Bit; }
            private set { _is64Bit = value; }
        }

        public void GetModules()
        {
            if (theProc == null)
                return;
            if (_is64Bit && IntPtr.Size != 8)
            {
                Debug.WriteLine("WARNING: Game is x64, but your Trainer is x86! You will be missing some modules, change your Trainer's Solution Platform.");
            }
            else if (!_is64Bit && IntPtr.Size == 8)
            {
                Debug.WriteLine("WARNING: Game is x86, but your Trainer is x64! You will be missing some modules, change your Trainer's Solution Platform.");
            }
            modules.Clear();
            foreach (ProcessModule Module in theProc.Modules)
            {
                if (!string.IsNullOrEmpty(Module.ModuleName) && !modules.ContainsKey(Module.ModuleName))
                    modules.Add(Module.ModuleName, Module.BaseAddress);
            }
            Debug.WriteLine("Found " + modules.Count() + " process modules.");
        }

        public int GetProcIdFromName(string name)
        {
            Process[] processlist = Process.GetProcesses();
            if (name.ToLower().Contains(".exe"))
                name = name.Replace(".exe", "");
            if (name.ToLower().Contains(".bin"))
                name = name.Replace(".bin", "");
            foreach (Process theprocess in processlist)
            {
                if (theprocess.ProcessName.Equals(name, StringComparison.CurrentCultureIgnoreCase))
                    return theprocess.Id;
            }
            return 0;
        }

        public string LoadCode(string name, string iniFile)
        {
            StringBuilder returnCode = new StringBuilder(1024);
            uint read_ini_result;
            if (iniFile != "")
            {
                if (File.Exists(iniFile))
                    read_ini_result = GetPrivateProfileString("codes", name, "", returnCode, (uint)returnCode.Capacity, iniFile);
                else
                    Debug.WriteLine("ERROR: ini file \"" + iniFile + "\" not found!");
            }
            else
                returnCode.Append(name);
            return returnCode.ToString();
        }

        public Dictionary<string, IntPtr> modules = new Dictionary<string, IntPtr>();

        private ProcessModule mainModule;

        #region protection
        [Flags]
        public enum MemoryProtection : uint
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        public bool ChangeProtection(string code, MemoryProtection newProtection, out MemoryProtection oldProtection, string file = "")
        {
            UIntPtr theCode = GetCode(code, file);
            if (theCode == UIntPtr.Zero || pHandle == IntPtr.Zero)
            {
                oldProtection = default;
                return false;
            }
            return VirtualProtectEx(pHandle, theCode, (IntPtr)(Is64Bit ? 8 : 4), newProtection, out oldProtection);
        }
        #endregion

        #region readMemory
        public float ReadFloat(string code, string file = "", bool round = true)
        {
            byte[] memory = new byte[4];
            UIntPtr theCode;
            theCode = GetCode(code, file);
            try
            {
                if (ReadProcessMemory(pHandle, theCode, memory, (UIntPtr)4, IntPtr.Zero))
                {
                    float address = BitConverter.ToSingle(memory, 0);
                    float returnValue = (float)address;
                    if (round)
                        returnValue = (float)Math.Round(address, 2);
                    return returnValue;
                }
                else
                    return 0;
            }
            catch
            {
                return 0;
            }
        }

        public string ReadString(string code, string file = "", int length = 32, bool zeroTerminated = true, Encoding stringEncoding = null)
        {
            if (stringEncoding == null)
                stringEncoding = Encoding.UTF8;
            byte[] memoryNormal = new byte[length];
            UIntPtr theCode;
            theCode = GetCode(code, file);

            if (ReadProcessMemory(pHandle, theCode, memoryNormal, (UIntPtr)length, IntPtr.Zero))
                return (zeroTerminated) ? stringEncoding.GetString(memoryNormal).Split('\0')[0] : stringEncoding.GetString(memoryNormal);
            else
                return "";
        }

        public int ReadInt(string code, string file = "")
        {
            byte[] memory = new byte[4];
            UIntPtr theCode;
            theCode = GetCode(code, file);
            if (ReadProcessMemory(pHandle, theCode, memory, (UIntPtr)4, IntPtr.Zero))
                return BitConverter.ToInt32(memory, 0);
            else
                return 0;
        }

        public int ReadByte(string code, string file = "")
        {
            byte[] memoryTiny = new byte[1];

            UIntPtr theCode = GetCode(code, file);

            if (ReadProcessMemory(pHandle, theCode, memoryTiny, (UIntPtr)1, IntPtr.Zero))
                return memoryTiny[0];

            return 0;
        }
        #endregion

        #region writeMemory
        public bool WriteMemory(string code, string type, string write, string file = "", Encoding stringEncoding = null, bool RemoveWriteProtection = true)
        {
            byte[] memory = new byte[4];
            int size = 4;

            UIntPtr theCode;
            theCode = GetCode(code, file);

            if (type.ToLower() == "float")
            {
                write = Convert.ToString(float.Parse(write, CultureInfo.InvariantCulture));
                memory = BitConverter.GetBytes(Convert.ToSingle(write));
                size = 4;
            }
            else if (type.ToLower() == "int")
            {
                memory = BitConverter.GetBytes(Convert.ToInt32(write));
                size = 4;
            }
            else if (type.ToLower() == "byte")
            {
                memory = new byte[1];
                memory[0] = Convert.ToByte(write, 16);
                size = 1;
            }
            else if (type.ToLower() == "2bytes")
            {
                memory = new byte[2];
                memory[0] = (byte)(Convert.ToInt32(write) % 256);
                memory[1] = (byte)(Convert.ToInt32(write) / 256);
                size = 2;
            }
            else if (type.ToLower() == "bytes")
            {
                if (write.Contains(",") || write.Contains(" ")) //check if it's a proper array
                {
                    string[] stringBytes;
                    if (write.Contains(","))
                        stringBytes = write.Split(',');
                    else
                        stringBytes = write.Split(' ');
                    //Debug.WriteLine("write:" + write + " stringBytes:" + stringBytes);

                    int c = stringBytes.Count();
                    memory = new byte[c];
                    for (int i = 0; i < c; i++)
                    {
                        memory[i] = Convert.ToByte(stringBytes[i], 16);
                    }
                    size = stringBytes.Count();
                }
                else //wasnt array, only 1 byte
                {
                    memory = new byte[1];
                    memory[0] = Convert.ToByte(write, 16);
                    size = 1;
                }
            }
            else if (type.ToLower() == "double")
            {
                memory = BitConverter.GetBytes(Convert.ToDouble(write));
                size = 8;
            }
            else if (type.ToLower() == "long")
            {
                memory = BitConverter.GetBytes(Convert.ToInt64(write));
                size = 8;
            }
            else if (type.ToLower() == "string")
            {
                if (stringEncoding == null)
                    memory = Encoding.UTF8.GetBytes(write);
                else
                    memory = stringEncoding.GetBytes(write);
                size = memory.Length;
            }

            //Debug.Write("DEBUG: Writing bytes [TYPE:" + type + " ADDR:" + theCode + "] " + String.Join(",", memory) + Environment.NewLine);
            MemoryProtection OldMemProt = 0x00;
            bool WriteProcMem = false;
            if (RemoveWriteProtection)
                ChangeProtection(code, MemoryProtection.ExecuteReadWrite, out OldMemProt); // change protection
            WriteProcMem = WriteProcessMemory(pHandle, theCode, memory, (UIntPtr)size, IntPtr.Zero);
            if (RemoveWriteProtection)
                ChangeProtection(code, OldMemProt, out _); // restore
            return WriteProcMem;
        }
        #endregion

        public UIntPtr GetCode(string name, string path = "", int size = 8)
        {
            string theCode = "";
            if (Is64Bit)
            {
                if (size == 8) size = 16;
                return Get64BitCode(name, path, size);
            }
            if (path != "")
                theCode = LoadCode(name, path);
            else
                theCode = name;
            if (theCode == "")
            {
                return UIntPtr.Zero;
            }
            if (theCode.Contains(" "))
                theCode = theCode.Replace(" ", String.Empty);
            if (!theCode.Contains("+") && !theCode.Contains(",")) return new UIntPtr(Convert.ToUInt32(theCode, 16));
            string newOffsets = theCode;
            if (theCode.Contains("+"))
                newOffsets = theCode.Substring(theCode.IndexOf('+') + 1);
            byte[] memoryAddress = new byte[size];
            if (newOffsets.Contains(','))
            {
                List<int> offsetsList = new List<int>();

                string[] newerOffsets = newOffsets.Split(',');
                foreach (string oldOffsets in newerOffsets)
                {
                    string test = oldOffsets;
                    if (oldOffsets.Contains("0x")) test = oldOffsets.Replace("0x", "");
                    int preParse = 0;
                    if (!oldOffsets.Contains("-"))
                        preParse = Int32.Parse(test, NumberStyles.AllowHexSpecifier);
                    else
                    {
                        test = test.Replace("-", "");
                        preParse = Int32.Parse(test, NumberStyles.AllowHexSpecifier);
                        preParse = preParse * -1;
                    }
                    offsetsList.Add(preParse);
                }
                int[] offsets = offsetsList.ToArray();
                if (theCode.Contains("base") || theCode.Contains("main"))
                    ReadProcessMemory(pHandle, (UIntPtr)((int)mainModule.BaseAddress + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
                else if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains("+"))
                {
                    string[] moduleName = theCode.Split('+');
                    IntPtr altModule = IntPtr.Zero;
                    if (!moduleName[0].ToLower().Contains(".dll") && !moduleName[0].ToLower().Contains(".exe") && !moduleName[0].ToLower().Contains(".bin"))
                    {
                        string theAddr = moduleName[0];
                        if (theAddr.Contains("0x")) theAddr = theAddr.Replace("0x", "");
                        altModule = (IntPtr)Int32.Parse(theAddr, NumberStyles.HexNumber);
                    }
                    else
                    {
                        try
                        {
                            altModule = modules[moduleName[0]];
                        }
                        catch
                        {
                            Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                            Debug.WriteLine("Modules: " + string.Join(",", modules));
                        }
                    }
                    ReadProcessMemory(pHandle, (UIntPtr)((int)altModule + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
                }
                else
                    ReadProcessMemory(pHandle, (UIntPtr)(offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
                uint num1 = BitConverter.ToUInt32(memoryAddress, 0);
                UIntPtr base1 = (UIntPtr)0;
                for (int i = 1; i < offsets.Length; i++)
                {
                    base1 = new UIntPtr(Convert.ToUInt32(num1 + offsets[i]));
                    ReadProcessMemory(pHandle, base1, memoryAddress, (UIntPtr)size, IntPtr.Zero);
                    num1 = BitConverter.ToUInt32(memoryAddress, 0);
                }
                return base1;
            }
            else
            {
                int trueCode = Convert.ToInt32(newOffsets, 16);
                IntPtr altModule = IntPtr.Zero;
                if (theCode.ToLower().Contains("base") || theCode.ToLower().Contains("main"))
                    altModule = mainModule.BaseAddress;
                else if (!theCode.ToLower().Contains("base") && !theCode.ToLower().Contains("main") && theCode.Contains("+"))
                {
                    string[] moduleName = theCode.Split('+');
                    if (!moduleName[0].ToLower().Contains(".dll") && !moduleName[0].ToLower().Contains(".exe") && !moduleName[0].ToLower().Contains(".bin"))
                    {
                        string theAddr = moduleName[0];
                        if (theAddr.Contains("0x")) theAddr = theAddr.Replace("0x", "");
                        altModule = (IntPtr)Int32.Parse(theAddr, NumberStyles.HexNumber);
                    }
                    else
                    {
                        try
                        {
                            altModule = modules[moduleName[0]];
                        }
                        catch
                        {
                            Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                            Debug.WriteLine("Modules: " + string.Join(",", modules));
                        }
                    }
                }
                else
                    altModule = modules[theCode.Split('+')[0]];
                return (UIntPtr)((int)altModule + trueCode);
            }
        }

        public UIntPtr Get64BitCode(string name, string path = "", int size = 16)
        {
            string theCode = "";
            if (path != "")
                theCode = LoadCode(name, path);
            else
                theCode = name;

            if (theCode == "")
                return UIntPtr.Zero;

            // remove spaces
            if (theCode.Contains(" "))
                theCode.Replace(" ", String.Empty);

            string newOffsets = theCode;
            if (theCode.Contains("+"))
                newOffsets = theCode.Substring(theCode.IndexOf('+') + 1);

            byte[] memoryAddress = new byte[size];

            if (!theCode.Contains("+") && !theCode.Contains(",")) return new UIntPtr(Convert.ToUInt64(theCode, 16));

            if (newOffsets.Contains(','))
            {
                List<Int64> offsetsList = new List<Int64>();

                string[] newerOffsets = newOffsets.Split(',');
                foreach (string oldOffsets in newerOffsets)
                {
                    string test = oldOffsets;
                    if (oldOffsets.Contains("0x")) test = oldOffsets.Replace("0x", "");
                    Int64 preParse = 0;
                    if (!oldOffsets.Contains("-"))
                        preParse = Int64.Parse(test, NumberStyles.AllowHexSpecifier);
                    else
                    {
                        test = test.Replace("-", "");
                        preParse = Int64.Parse(test, NumberStyles.AllowHexSpecifier);
                        preParse = preParse * -1;
                    }
                    offsetsList.Add(preParse);
                }
                Int64[] offsets = offsetsList.ToArray();

                if (theCode.Contains("base") || theCode.Contains("main"))
                    ReadProcessMemory(pHandle, (UIntPtr)((Int64)mainModule.BaseAddress + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
                else if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains("+"))
                {
                    string[] moduleName = theCode.Split('+');
                    IntPtr altModule = IntPtr.Zero;
                    if (!moduleName[0].ToLower().Contains(".dll") && !moduleName[0].ToLower().Contains(".exe") && !moduleName[0].ToLower().Contains(".bin"))
                        altModule = (IntPtr)Int64.Parse(moduleName[0], System.Globalization.NumberStyles.HexNumber);
                    else
                    {
                        try
                        {
                            altModule = modules[moduleName[0]];
                        }
                        catch
                        {
                            Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                            Debug.WriteLine("Modules: " + string.Join(",", modules));
                        }
                    }
                    ReadProcessMemory(pHandle, (UIntPtr)((Int64)altModule + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
                }
                else // no offsets
                    ReadProcessMemory(pHandle, (UIntPtr)(offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);

                Int64 num1 = BitConverter.ToInt64(memoryAddress, 0);

                UIntPtr base1 = (UIntPtr)0;

                for (int i = 1; i < offsets.Length; i++)
                {
                    base1 = new UIntPtr(Convert.ToUInt64(num1 + offsets[i]));
                    ReadProcessMemory(pHandle, base1, memoryAddress, (UIntPtr)size, IntPtr.Zero);
                    num1 = BitConverter.ToInt64(memoryAddress, 0);
                }
                return base1;
            }
            else
            {
                Int64 trueCode = Convert.ToInt64(newOffsets, 16);
                IntPtr altModule = IntPtr.Zero;
                if (theCode.Contains("base") || theCode.Contains("main"))
                    altModule = mainModule.BaseAddress;
                else if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains("+"))
                {
                    string[] moduleName = theCode.Split('+');
                    if (!moduleName[0].ToLower().Contains(".dll") && !moduleName[0].ToLower().Contains(".exe") && !moduleName[0].ToLower().Contains(".bin"))
                    {
                        string theAddr = moduleName[0];
                        if (theAddr.Contains("0x")) theAddr = theAddr.Replace("0x", "");
                        altModule = (IntPtr)Int64.Parse(theAddr, NumberStyles.HexNumber);
                    }
                    else
                    {
                        try
                        {
                            altModule = modules[moduleName[0]];
                        }
                        catch
                        {
                            Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                            Debug.WriteLine("Modules: " + string.Join(",", modules));
                        }
                    }
                }
                else
                    altModule = modules[theCode.Split('+')[0]];
                return (UIntPtr)((Int64)altModule + trueCode);
            }
        }
#if WINXP
#endif

        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }

        public static void SuspendProcess(int pid)
        {
            var process = Process.GetProcessById(pid);

            if (process.ProcessName == string.Empty)
                return;

            foreach (ProcessThread pT in process.Threads)
            {
                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);
                if (pOpenThread == IntPtr.Zero)
                    continue;

                SuspendThread(pOpenThread);
                CloseHandle(pOpenThread);
            }
        }

        public static void ResumeProcess(int pid)
        {
            var process = Process.GetProcessById(pid);
            if (process.ProcessName == string.Empty)
                return;

            foreach (ProcessThread pT in process.Threads)
            {
                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);
                if (pOpenThread == IntPtr.Zero)
                    continue;

                var suspendCount = 0;
                do
                {
                    suspendCount = ResumeThread(pOpenThread);
                } while (suspendCount > 0);
                CloseHandle(pOpenThread);
            }
        }

#if WINXP
#else
#endif

        void AppendAllBytes(string path, byte[] bytes)
        {
            using (var stream = new FileStream(path, FileMode.Append))
            {
                stream.Write(bytes, 0, bytes.Length);
            }
        }

        public byte[] FileToBytes(string path, bool dontDelete = false)
        {
            byte[] newArray = File.ReadAllBytes(path);
            if (!dontDelete)
                File.Delete(path);
            return newArray;
        }

        public string MSize()
        {
            if (Is64Bit)
                return ("x16");
            else
                return ("x8");
        }

        public static string ByteArrayToHexString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            int i = 1;
            foreach (byte b in ba)
            {
                if (i == 16)
                {
                    hex.AppendFormat("{0:x2}{1}", b, Environment.NewLine);
                    i = 0;
                }
                else
                    hex.AppendFormat("{0:x2} ", b);
                i++;
            }
            return hex.ToString().ToUpper();
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
            {
                hex.AppendFormat("{0:x2} ", b);
            }
            return hex.ToString();
        }

#if WINXP
#else

        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public UIntPtr minimumApplicationAddress;
            public UIntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }

        public struct MEMORY_BASIC_INFORMATION32
        {
            public UIntPtr BaseAddress;
            public UIntPtr AllocationBase;
            public uint AllocationProtect;
            public uint RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public struct MEMORY_BASIC_INFORMATION64
        {
            public UIntPtr BaseAddress;
            public UIntPtr AllocationBase;
            public uint AllocationProtect;
            public uint __alignment1;
            public ulong RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
            public uint __alignment2;
        }

        public struct MEMORY_BASIC_INFORMATION
        {
            public UIntPtr BaseAddress;
            public UIntPtr AllocationBase;
            public uint AllocationProtect;
            public long RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public ulong GetMinAddress()
        {
            SYSTEM_INFO SI;
            GetSystemInfo(out SI);
            return (ulong)SI.minimumApplicationAddress;
        }

        public bool DumpMemory(string file = "dump.dmp")
        {
            Debug.Write("[DEBUG] memory dump starting... (" + DateTime.Now.ToString("h:mm:ss tt") + ")" + Environment.NewLine);
            SYSTEM_INFO sys_info = new SYSTEM_INFO();
            GetSystemInfo(out sys_info);
            UIntPtr proc_min_address = sys_info.minimumApplicationAddress;
            UIntPtr proc_max_address = sys_info.maximumApplicationAddress;
            Int64 proc_min_address_l = (Int64)proc_min_address;
            Int64 proc_max_address_l = (Int64)theProc.VirtualMemorySize64 + proc_min_address_l;

            //int arrLength = 0;
            if (File.Exists(file))
                File.Delete(file);
            MEMORY_BASIC_INFORMATION memInfo = new MEMORY_BASIC_INFORMATION();
            while (proc_min_address_l < proc_max_address_l)
            {
                VirtualQueryEx(pHandle, proc_min_address, out memInfo);
                byte[] buffer = new byte[(Int64)memInfo.RegionSize];
                UIntPtr test = (UIntPtr)((Int64)memInfo.RegionSize);
                UIntPtr test2 = (UIntPtr)((Int64)memInfo.BaseAddress);
                ReadProcessMemory(pHandle, test2, buffer, test, IntPtr.Zero);
                AppendAllBytes(file, buffer);
                proc_min_address_l += (Int64)memInfo.RegionSize;
                proc_min_address = new UIntPtr((ulong)proc_min_address_l);
            }
            Debug.Write("[DEBUG] memory dump completed. Saving dump file to " + file + ". (" + DateTime.Now.ToString("h:mm:ss tt") + ")" + Environment.NewLine);
            return true;
        }
#endif
    }
}
