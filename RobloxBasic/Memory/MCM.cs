using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace RobloxBasic.Memory
{
    class MCM
    {
        public static Mem m = new Mem();
        public static IntPtr mcWinHandle;
        public static uint mcWinProcId;
        public static bool loaded = false;
        public static int loading = 0;

        #region imports
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
        [DllImport("user32.dll")]
        static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
        [DllImport("user32.dll")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")]
        public static extern bool GetAsyncKeyState(char vKey);
        #endregion

        public struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }
        public static void log(string str)
        {
            Console.WriteLine("[DEBUG]: " + str);
        }
        public static void logf(string str)
        {
            Console.WriteLine("[DEBUG]: " + str);
        }
        public static void msgbox(string str, string title = "RobloxBetaPlayer.exe")
        {
            MessageBox.Show(str, title);
        }
        public static RECT getRobloxtRect()
        {
            RECT rectMC = new RECT();
            GetWindowRect(mcWinHandle, out rectMC);
            return rectMC;
        }
        public static bool isRobloxFocused()
        {
            StringBuilder sb = new StringBuilder("Roblox".Length + 1);
            GetWindowText(GetForegroundWindow(), sb, "Roblox".Length + 1);
            return sb.ToString().CompareTo("Roblox") == 0;
        }
        public static void openWindowHost()
        {
            Process[] procs = Process.GetProcessesByName("RobloxPlayerBeta");
            mcWinHandle = procs[0].MainWindowHandle;
            mcWinProcId = (uint)procs[0].Id;
        }
    }
}
