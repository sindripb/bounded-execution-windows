// Read-only console membership/visibility guard. No console allocation or attachment.
using System;
using System.IO;
using System.Runtime.InteropServices;
public static class ConsoleIdentity {
    [DllImport("kernel32",SetLastError=true)] static extern uint GetConsoleProcessList([Out] uint[] list,uint count);
    [DllImport("kernel32")] static extern IntPtr GetConsoleWindow();
    [DllImport("user32")] static extern bool IsWindowVisible(IntPtr window);
    public static uint[] HiddenWith(uint expected){
        uint[] list=new uint[4];uint count=GetConsoleProcessList(list,4);
        if(count<1||count>4||Array.IndexOf(list,expected)<0)throw new IOException("ExistingOwnerConsoleRequired");
        IntPtr window=GetConsoleWindow();if(window!=IntPtr.Zero&&IsWindowVisible(window))throw new IOException("VisibleConsoleRejected");
        Array.Resize(ref list,(int)count);return list;
    }
}
