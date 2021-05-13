using RobloxBasic.ClientBase.Keybinds;
using RobloxBasic.Memory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RobloxBasic
{
    class RobloxThread
    {
        public static void onStart()
        {
            KeybindHandler.clientKeyDownEvent += keyDown;
            KeybindHandler.clientKeyHeldEvent += keyHeld;
            KeybindHandler.clientKeyUpEvent += keyUp;
            MCM.log("Started");
        }

        public static void onTick() { }
        
        private static void keyDown(object sender, clientKeyEvent e)
        {
            MCM.log($"Key Down Event Triggered : ( KeyID:{(int)e.key} , KeyChar:{e.key} )");
        }

        private static void keyHeld(object sender, clientKeyEvent e) { }

        private static void keyUp(object sender, clientKeyEvent e) { }
    }
}
