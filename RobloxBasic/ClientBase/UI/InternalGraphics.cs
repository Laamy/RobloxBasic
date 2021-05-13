using Capture;
using Capture.Hook;
using Capture.Hook.Common;
using Capture.Interface;
using RobloxBasic.Memory;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RobloxBasic.ClientBase.UI
{
    class InternalGraphics
    {
        static CaptureProcess _captureProcess;
        static int processId = 0;
        static Process _process;

        public static void inject()
        {
            if (_captureProcess == null)
                AttachProcess();
            else
            {
                HookManager.RemoveHookedProcess(_captureProcess.Process.Id);
                _captureProcess.CaptureInterface.Disconnect();
                _captureProcess = null;
            }
        }

        public static void Invalidate() => _captureProcess.CaptureInterface.DrawOverlayInGame(new Overlay { Elements = renderElements, });

        public static List<IOverlayElement> renderElements = new List<IOverlayElement>();

        private static void AttachProcess()
        {
            string exeName = Path.GetFileNameWithoutExtension("RobloxPlayerBeta.exe");

            Process[] processes = Process.GetProcessesByName(exeName);
            foreach (Process process in processes)
            {
                if (process.MainWindowHandle == IntPtr.Zero)
                    continue;
                if (HookManager.IsHooked(process.Id))
                    continue;

                Direct3DVersion direct3DVersion = Direct3DVersion.Direct3D11;

                CaptureConfig cc = new CaptureConfig()
                {
                    Direct3DVersion = direct3DVersion,
                    ShowOverlay = true
                };

                processId = process.Id;
                _process = process;

                var captureInterface = new CaptureInterface();
                captureInterface.RemoteMessage += new MessageReceivedEvent(CaptureInterface_RemoteMessage);
                _captureProcess = new CaptureProcess(process, cc, captureInterface);

                break;
            }
            Thread.Sleep(10);

            if (_captureProcess == null)
                MCM.log("No executable found matching: '" + exeName + ".exe'");
        }

        static void CaptureInterface_RemoteMessage(MessageReceivedEventArgs message)
        {
            MCM.logf(message.Message);
        }
    }
}
