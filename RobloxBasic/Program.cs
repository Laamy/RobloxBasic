using RobloxBasic.ClientBase.Keybinds;
using RobloxBasic.ClientBase.Language;
using RobloxBasic.ClientBase.UI;
using RobloxBasic.Memory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RobloxBasic
{
    class Program
    {
        public static EventHandler<EventArgs> mainLoop;

        static void Main(string[] args)
        {
            try
            {
                KeybindHandler kh = new KeybindHandler(); // setup handlers
                LanguageHandler lh = new LanguageHandler(); // Setup script execution

                rst:

                try
                {
                    MCM.openWindowHost();
                    MCM.m.OpenRoblox();
                }
                catch
                {
                    Console.WriteLine("Please run roblox first! (Click any key to reattach)");
                    Console.ReadKey();
                    goto rst;
                }

                RobloxThread.onStart(); // invoke onStart

                while (true) // Loop lmao
                {
                    try // catch & ignore errors
                    {
                        mainLoop.Invoke(null, new EventArgs()); // invoke all key events script ticks etc.
                        RobloxThread.onTick(); // invoke onTick()
                                               // Thread.Sleep(1);
                    }
                    catch
                    {

                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.StackTrace);
                MCM.msgbox("Exploit crashed D: please report any and all errors/crashes too our discord ;3");
            }
        }
    }
}
