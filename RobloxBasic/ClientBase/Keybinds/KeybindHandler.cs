﻿using RobloxBasic.Memory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RobloxBasic.ClientBase.Keybinds
{
    public class KeybindHandler
    {
        public static bool isKeyDown(char key)
        {
            if (MCM.isRobloxFocused())
                return MCM.GetAsyncKeyState(key);
            return false;
        }

        public static KeybindHandler handler;
        public static EventHandler<clientKeyEvent> clientKeyDownEvent;
        public static EventHandler<clientKeyEvent> clientKeyHeldEvent;
        public static EventHandler<clientKeyEvent> clientKeyUpEvent;

        Dictionary<char, uint> downBuffs = new Dictionary<char, uint>();
        Dictionary<char, bool> noKey = new Dictionary<char, bool>();

        Dictionary<char, uint> releaseBuffs = new Dictionary<char, uint>();
        Dictionary<char, bool> yesKey = new Dictionary<char, bool>();

        public KeybindHandler()
        {
            handler = this;
            Console.WriteLine("Starting key thread");
            for (char c = (char)0; c < 0xFF; c++)
            {
                downBuffs.Add(c, 0);
                noKey.Add(c, true);
            }
            for (char c = (char)0; c < 0xFF; c++)
            {
                releaseBuffs.Add(c, 0);
                yesKey.Add(c, true);
            }
            Program.mainLoop += (object sen, EventArgs e) =>
            {
                try
                {
                    if (MCM.isRobloxFocused())
                    {
                        for (char c = (char)0; c < 0xFF; c++)
                        {
                            noKey[c] = true;
                            yesKey[c] = false;
                            if (MCM.GetAsyncKeyState(c))
                            {
                                if (clientKeyHeldEvent != null)
                                    clientKeyHeldEvent.Invoke(this, new clientKeyEvent(c));
                                noKey[c] = false;
                                if (downBuffs[c] > 0)
                                {
                                    continue;
                                }
                                downBuffs[c]++;
                                try
                                {
                                    if (clientKeyDownEvent != null)
                                    {
                                        clientKeyDownEvent.Invoke(this, new clientKeyEvent(c));
                                    }
                                }
                                catch (Exception) { }
                            }
                            else
                            {
                                yesKey[c] = true;
                                if (releaseBuffs[c] > 0)
                                {
                                    continue;
                                }
                                releaseBuffs[c]++;
                                if (clientKeyUpEvent != null)
                                {
                                    try
                                    {
                                        clientKeyUpEvent.Invoke(this, new clientKeyEvent(c));
                                    }
                                    catch (Exception) { }
                                }
                            }
                            if (noKey[c])
                            {
                                downBuffs[c] = 0;
                            }
                            if (!yesKey[c])
                            {
                                releaseBuffs[c] = 0;
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine("KeyHandler failed a task!");
                }
            };

            clientKeyDownEvent += dispatchKeybinds;
            Console.WriteLine("key shit started");
        }

        public void dispatchKeybinds(object sender, clientKeyEvent e)
        {
            // modules loop...
        }
    }
    public class clientKeyEvent : EventArgs
    {
        public char key;
        public clientKeyEvent(char key)
        {
            this.key = key;
        }
    }
}
