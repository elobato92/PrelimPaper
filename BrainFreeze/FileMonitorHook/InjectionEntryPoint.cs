// RemoteFileMonitor (File: FileMonitorHook\InjectionEntryPoint.cs)
//
// Copyright (c) 2017 Justin Stenning
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// Please visit https://easyhook.github.io for more information
// about the project, latest updates and other tutorials.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Management;
using System.Timers;
using System.Windows.Forms;
using System.Windows;

namespace FileMonitorHook
{
    /// <summary>
    /// EasyHook will look for a class implementing <see cref="EasyHook.IEntryPoint"/> during injection. This
    /// becomes the entry point within the target process after injection is complete.
    /// </summary>


    public class InjectionEntryPoint : EasyHook.IEntryPoint
    {
        int WanaCryCounter = 0;
        int WanaCryCounter2 = 0;
        int WanaCryCounter3 = 0;
        int JigsawCounter = 0;
        int JigsawCounter2 = 0;
        int LockyCounter = 0;
        int VipasanaCounter = 0;
        int VipasanaCounter2 = 0;
        int VipasanaCounter3 = 0;
        int VipasanaCounter4 = 0;
        int CerberCounter = 0;
        /// <summary>
        /// Reference to the server interface within FileMonitor
        /// </summary>
        ServerInterface _server = null;

        /// <summary>
        /// Message queue of all files accessed
        /// </summary>
        Queue<string> _messageQueue = new Queue<string>();
        //int killFlag = 0;

        /// <summary>
        /// EasyHook requires a constructor that matches <paramref name="context"/> and any additional parameters as provided
        /// in the original call to <see cref="EasyHook.RemoteHooking.Inject(int, EasyHook.InjectionOptions, string, string, object[])"/>.
        /// 
        /// Multiple constructors can exist on the same <see cref="EasyHook.IEntryPoint"/>, providing that each one has a corresponding Run method (e.g. <see cref="Run(EasyHook.RemoteHooking.IContext, string)"/>).
        /// </summary>
        /// <param name="context">The RemoteHooking context</param>
        /// <param name="channelName">The name of the IPC channel</param>
        public InjectionEntryPoint(
            EasyHook.RemoteHooking.IContext context,
            string channelName)
        {
            // Connect to server object using provided channel name
            _server = EasyHook.RemoteHooking.IpcConnectClient<ServerInterface>(channelName);

            // If Ping fails then the Run method will be not be called
            _server.Ping();
        }

        /// <summary>
        /// The main entry point for our logic once injected within the target process. 
        /// This is where the hooks will be created, and a loop will be entered until host process exits.
        /// EasyHook requires a matching Run method for the constructor
        /// </summary>
        /// <param name="context">The RemoteHooking context</param>
        /// <param name="channelName">The name of the IPC channel</param>
        public void Run(
            EasyHook.RemoteHooking.IContext context,
            string channelName)
        {
            // Injection is now complete and the server interface is connected
            _server.IsInstalled(EasyHook.RemoteHooking.GetCurrentProcessId());

            #region Install hooks

            // CreateFile https://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx
            var createFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"),
                new CreateFile_Delegate(CreateFile_Hook),
                this);

            // ReadFile https://msdn.microsoft.com/en-us/library/windows/desktop/aa365467(v=vs.85).aspx
            var readFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "ReadFile"),
                new ReadFile_Delegate(ReadFile_Hook),
                this);

            // WriteFile https://msdn.microsoft.com/en-us/library/windows/desktop/aa365747(v=vs.85).aspx
            var writeFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "WriteFile"),
                new WriteFile_Delegate(WriteFile_Hook),
                this);

            //NTDeviceIOControlFile https://msdn.microsoft.com/en-us/library/ms648411(v=vs.85).aspx (WanaCry)
            var NtDeviceIoControlFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("ntdll.dll", "NtDeviceIoControlFile"),
                new NtDeviceIoControlFile_Delegate(NtDeviceIoControlFile_Hook),
                this);

            //NtClose (WanaCry)
            var NtCloseHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("ntdll.dll", "NtClose"),
                new NtClose_Delegate(NtClose_Hook),
                this);
            //NtQueryVolumeInformationFile (WanaCry)
            var NtQueryVolumeInformationFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("ntdll.dll", "NtQueryVolumeInformationFile"),
                new NtQueryVolumeInformationFile_Delegate(NtQueryVolumeInformationFile_Hook),
                this);

            //NtQueryInformationToken (JigSaw)
            var NtQueryInformationTokenHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("ntdll.dll", "NtQueryInformationToken"),
                new NtQueryInformationToken_Delegate(NtQueryInformationToken_Hook),
                this);
            //NtQueryInformationProcess (Jigsaw)
            var NtQueryInformationProcessHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("ntdll.dll", "NtQueryInformationProcess"),
                new NtQueryInformationProcess_Delegate(NtQueryInformationProcess_Hook),
                this);

            //NtQueryAttributes (Locky)
            var NtQueryAttributesFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("ntdll.dll", "NtQueryAttributesFile"),
                new NtQueryAttributesFile_Delegate(NtQueryAttributesFile_Hook),
                this);

            //NtQueryInformationFile (Vipsana)
            var NtQueryInformationFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("ntdll.dll", "NtQueryInformationFile"),
                new NtQueryInformationFile_Delegate(NtQueryInformationFile_Hook),
                this);
            //NtSetInformationFile (Vipasana)
            var NtSetInformationFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("ntdll.dll", "NtSetInformationFile"),
                new NtSetInformationFile_Delegate(NtSetInformationFile_Hook),
                this);
            //NtReadFile (vipasana)
            var NtReadFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("ntdll.dll", "NtReadFile"),
                new NtReadFile_Delegate(NtReadFile_Hook),
                this);
            //NtWriteFile (Vipasana)
            var NtWriteFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("ntdll.dll", "NtWriteFile"),
                new NtWriteFile_Delegate(NtWriteFile_Hook),
                this);
            //NtWaitForSingleObject (cerber)
            var NtWaitForSingleObjectHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("ntdll.dll", "NtWaitForSingleObject"),
                new NtWaitForSingleObject_Delegate(NtWaitForSingleObject_Hook),
                this);

            /*var NtQuerySystemInformationHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("ntdll.dll", "NtQuerySystemInformation"),
                new NtQuerySystemInformation_Delegate(NtQuerySystemInformation_Hook),
                this);*/
            #endregion

            // Activate hooks on all threads except the current thread
            createFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            readFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            writeFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });

            #region enable hooks

            _server.ReportMessage("CreateFile, ReadFile, and Writefile hooks installed");

            //NtQuerySystemInformationHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });

            //NtDeviceIoControlFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            //NtCloseHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            //NtQueryVolumeInformationFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });

            //_server.ReportMessage("Installed Wanacry hooks!");

            NtQueryInformationTokenHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            NtQueryInformationProcessHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });

            _server.ReportMessage("Installed JigSaw hooks!");
            
            //NtQueryAttributesFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });


            //_server.ReportMessage("Installed Locky hook!");

            //NtQueryInformationFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            //NtSetInformationFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            //NtReadFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            //NtWriteFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            //_server.ReportMessage("Installed Vipasana hooks!");

            //NtWaitForSingleObjectHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            
            //_server.ReportMessage("Installed Cerber hook!");
            #endregion

            // Wake up the process (required if using RemoteHooking.CreateAndInject)
            EasyHook.RemoteHooking.WakeUpProcess();

            try
            {
                // Loop until FileMonitor closes (i.e. IPC fails)
                while (true)
                {
                    System.Threading.Thread.Sleep(50);

                    string[] queued = null;

                    lock (_messageQueue)
                    {
                        queued = _messageQueue.ToArray();
                        _messageQueue.Clear();
                    }

                    // Send newly monitored file accesses to FileMonitor
                    if (queued != null && queued.Length > 0)
                    {
                        _server.ReportMessages(queued);
                    }
                    else
                    {
                        _server.Ping();
                    }
                }
            }
            catch
            {
                // Ping() or ReportMessages() will raise an exception if host is unreachable
            }

            // Remove hooks
            createFileHook.Dispose();
            readFileHook.Dispose();
            writeFileHook.Dispose();
            //NtDeviceIoControlFileHook.Dispose();
            //NtCloseHook.Dispose();
            NtQueryVolumeInformationFileHook.Dispose();
            NtQueryInformationTokenHook.Dispose();
            //NtQueryInformationProcessHook.Dispose();
            //NtQueryAttributesFileHook.Dispose();
            //NtQueryInformationFileHook.Dispose();
            //NtSetInformationFileHook.Dispose();
            //NtReadFileHook.Dispose();
            //NtWriteFileHook.Dispose();
            //NtWaitForSingleObjectHook.Dispose();
            //NtQuerySystemInformationHook.Dispose();

            // Finalise cleanup of hooks
            EasyHook.LocalHook.Release();
        }

        /// <summary>
        /// P/Invoke to determine the filename from a file handle
        /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa364962(v=vs.85).aspx
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpszFilePath"></param>
        /// <param name="cchFilePath"></param>
        /// <param name="dwFlags"></param>
        /// <returns></returns>
        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern uint GetFinalPathNameByHandle(IntPtr hFile, [MarshalAs(UnmanagedType.LPTStr)] StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

        /// <summary>
        /// Kill a process, and all of its children, grandchildren, etc.
        /// </summary>
        /// <param name="pid">Process ID.</param>
        public static void KillProcessAndChildren(int pid)
        {
            // Cannot close 'system idle process'.
            if (pid == 0)
            {
                return;
            }
            ManagementObjectSearcher searcher = new ManagementObjectSearcher
             ("Select * From Win32_Process Where ParentProcessID=" + pid);
            ManagementObjectCollection moc = searcher.Get();
            foreach (ManagementObject mo in moc)
            {
                KillProcessAndChildren(Convert.ToInt32(mo["ProcessID"]));
            }
            try
            {
                Process proc = Process.GetProcessById(pid);
                proc.Kill();
            }
            catch (ArgumentException)
            {
                // Process already exited.
            }
        }

        #region NtQuerySystemInformation Hook (example)

        //delegate...
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate long NtQuerySystemInformation_Delegate(
          SystemInformation SystemInformationClass,
          IntPtr SystemInformation,
          uint SystemInformationLength,
          out IntPtr ReturnLength
        );

        //original...
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern long NtQuerySystemInformation(
          SystemInformation SystemInformationClass,
          IntPtr SystemInformation,
          uint SystemInformationLength,
          out IntPtr ReturnLength);

        //Hook...
        long NtQuerySystemInformation_Hook(
          SystemInformation SystemInformationClass,
          IntPtr SystemInformation,
          uint SystemInformationLength,
          out IntPtr ReturnLength)
        {
            //Do the redirected commands..
            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        // Add message to send to FileMonitor
                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: NtQuerySystemInformation",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId()));
                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            // now call the original API...
            return NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, out ReturnLength);
        }
        #endregion 

        #region NtDeviceIoControlFile Hook (WanaCry)
        /// <summary>
        /// The NtDeviceIoControlFile delegate, this is needed to create a delegate of our hook function <see cref="CreateFile_Hook(string, uint, uint, IntPtr, uint, uint, IntPtr)"/>.
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
                    CharSet = CharSet.Unicode,
                    SetLastError = true)]
        delegate int NtDeviceIoControlFile_Delegate(
                     IntPtr FileHandle,
                    IntPtr Event,
                    IntPtr ApcRoutine,
                    IntPtr ApcContext,
                    out IntPtr IoStatusBlock,
                    uint IoControlCode,
                    IntPtr InputBuffer,
                    uint InputBufferLength,
                    out IntPtr OutputBuffer,
                    uint OutputBufferLength);

        /// <summary>
        /// Using P/Invoke to call original method.
        /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx
        [DllImport("ntdll.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern int NtDeviceIoControlFile(
                    IntPtr FileHandle,
                    IntPtr Event,
                    IntPtr ApcRoutine,
                    IntPtr ApcContext,
                    out IntPtr IoStatusBlock,
                    uint IoControlCode,
                    IntPtr InputBuffer,
                    uint InputBufferLength,
                    out IntPtr OutputBuffer,
                    uint OutputBufferLength);
        /// <summary>
        /// The NtDeviceIoControlfile hook function. This will be called instead of the original deviceiocontrolfile once hooked.
        /// </summary>
        int NtDeviceIoControlFile_Hook(
                   IntPtr FileHandle,
                   IntPtr Event,
                   IntPtr ApcRoutine,
                   IntPtr ApcContext,
                   out IntPtr IoStatusBlock,
                   uint IoControlCode,
                   IntPtr InputBuffer,
                   uint InputBufferLength,
                   out IntPtr OutputBuffer,
                   uint OutputBufferLength)
        {
            //Do the redirected commands..
            try
            {
                WanaCryCounter++;
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        // Add message to send to FileMonitor
                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: NTDeviceIoControlFile COUNT:{2}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), WanaCryCounter));
                    }
                    if (WanaCryCounter >= 17000)// && WanaCryCounter2 >= 9765)// && WanaCryCounter3 >= 8605)
                    {
                        //MessageBox.Show("Malicious behaviour detected, press OK to terminate", "BrainFreeze", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                        _server.ReportMessage(string.Format("Criteria met for Wanacry\n(NtQuerySystemInformation:{0})(NtClose:{1}).\n Killing hooked process... \n<Press any key to exit>", WanaCryCounter, WanaCryCounter2));
                        KillProcessAndChildren(EasyHook.RemoteHooking.GetCurrentProcessId());
                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            // now call the original API...
            return NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, out IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, out OutputBuffer, OutputBufferLength);
        }

        #endregion

        #region NtClose (WanaCry)
        //Delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
    CharSet = CharSet.Unicode,
    SetLastError = true)]
        delegate int NtClose_Delegate(
        IntPtr Handle);

        //original
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern int NtClose(
            IntPtr Handle);

        //Hooked
        int NtClose_Hook(
            IntPtr Handle)
        {
            //Do the redirected commands..
            try
            {
                WanaCryCounter2++;
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        // Add message to send to FileMonitor
                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: NtClose COUNT:{2}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), WanaCryCounter2));
                    }
                    if (WanaCryCounter >= 17000 && WanaCryCounter2 >= 9765)// && WanaCryCounter3 >= 8605)
                    {
                        MessageBox.Show("Malicious behaviour detected, press OK to terminate", "BrainFreeze", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                        _server.ReportMessage(string.Format("Criteria met for Wanacry\n(NtQuerySystemInformation:{0})(NtClose:{1}).\n Killing hooked process... \n<Press any key to exit>",WanaCryCounter, WanaCryCounter2));
                        KillProcessAndChildren(EasyHook.RemoteHooking.GetCurrentProcessId());
                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            // now call the original API...
            return NtClose(Handle);
        }
        #endregion

        #region NtQueryVolumeInformationFile (WanaCry)
        //delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
    CharSet = CharSet.Unicode,
    SetLastError = true)]
        delegate int NtQueryVolumeInformationFile_Delegate(
            IntPtr FileHandle,
            IntPtr IOStatusBlock,
            IntPtr FsInformation,
            uint Length,
            IntPtr FsInfomationClass);
        //original
        [DllImport("ntdll.dll",
    CharSet = CharSet.Unicode,
    SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern int NtQueryVolumeInformationFile(
            IntPtr FileHandle,
            IntPtr IOStatusBlock,
            IntPtr FsInformation,
            uint Length,
            IntPtr FsInfomationClass);
        //hooked
        int NtQueryVolumeInformationFile_Hook(
            IntPtr FileHandle,
            IntPtr IOStatusBlock,
            IntPtr FsInformation,
            uint Length,
            IntPtr FsInfomationClass)
        {
            //Do the redirected commands..
            try
            {
                WanaCryCounter3++;
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        // Add message to send to FileMonitor
                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: NTQueryVolumeInfomationFile COUNT:{2}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), WanaCryCounter3));
                    }
                    if (WanaCryCounter >= 17000 && WanaCryCounter2 >= 9765 && WanaCryCounter3 >= 8605)
                    {
                        MessageBox.Show("Malicious behaviour detected, press OK to terminate", "BrainFreeze", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                        _server.ReportMessage(string.Format("Criteria met for Wanacry(NtQueryVolumeInformation). Killing hooked process... \n<Press any key to exit>"));
                        KillProcessAndChildren(EasyHook.RemoteHooking.GetCurrentProcessId());
                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            // now call the original API...
            return NtQueryVolumeInformationFile(FileHandle, IOStatusBlock, FsInformation, Length, FsInfomationClass);
        }
    

    #endregion

        #region NtQueryInformationToken Hook (Jigsaw)
    //delegate
    [UnmanagedFunctionPointer(CallingConvention.StdCall,
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    delegate int NtQueryInformationToken_Delegate(
         IntPtr TokenHandle,
         IntPtr TokenInformationClass,
         IntPtr TokenInformation,
         uint TokenInformationLength,
         IntPtr ReturnLength);

    //original
    [DllImport("ntdll.dll",
CharSet = CharSet.Unicode,
SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    static extern int NtQueryInformationToken(
         IntPtr TokenHandle,
         IntPtr TokenInformationClass,
         IntPtr TokenInformation,
         uint TokenInformationLength,
         IntPtr ReturnLength);

    //hooked
    int NtQueryInformationToken_Hook(
         IntPtr TokenHandle,
         IntPtr TokenInformationClass,
         IntPtr TokenInformation,
         uint TokenInformationLength,
         IntPtr ReturnLength)
    {
        //Do the redirected commands..
        try
        {
            JigsawCounter++;
            lock (this._messageQueue)
            {
                if (this._messageQueue.Count < 1000)
                {
                    // Add message to send to FileMonitor
                    this._messageQueue.Enqueue(
                        string.Format("[{0}:{1}]: NtQueryInformationToken COUNT:{2}",
                        EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), JigsawCounter));
                }
                if (JigsawCounter >= 8233 && JigsawCounter2>=8139)
                {
                    _server.ReportMessage(string.Format("Criteria met for Jigsaw. Killing hooked process... \n<Press any key to exit>"));
                    KillProcessAndChildren(EasyHook.RemoteHooking.GetCurrentProcessId());
                }
            }
        }
        catch
        {
            // swallow exceptions so that any issues caused by this code do not crash target process
        }
        // now call the original API...
        return NtQueryInformationToken(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength);
    }
        #endregion

        #region NtQueryInformationProcess (Jigsaw)
        //delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
    CharSet = CharSet.Unicode,
    SetLastError = true)]
        delegate int NtQueryInformationProcess_Delegate(
            IntPtr ProcessHandle,
            IntPtr ProcessInformationClass,
            out IntPtr ProcessInformation,
            uint ProcessInformationLength,
            out IntPtr ReturnLength);
        //original
        [DllImport("ntdll.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern int NtQueryInformationProcess(
                    IntPtr ProcessHandle,
                    IntPtr ProcessInformationClass,
                    out IntPtr ProcessInformation,
                    uint ProcessInformationLength,
                    out IntPtr ReturnLength);
        //hook
        int NtQueryInformationProcess_Hook(
                    IntPtr ProcessHandle,
                    IntPtr ProcessInformationClass,
                    out IntPtr ProcessInformation,
                    uint ProcessInformationLength,
                    out IntPtr ReturnLength)
        {
            //Do the redirected commands..
            try
            {
                JigsawCounter2++;
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        // Add message to send to FileMonitor
                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: NtQueryInformationProcess COUNT:{2}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), JigsawCounter2));
                    }
                    if (JigsawCounter >= 8233 && JigsawCounter2 >= 8139)
                    {
                        _server.ReportMessage(string.Format("Criteria met for Jigsaw(NtQueryInformationProcess). Killing hooked process... \n<Press any key to exit>"));
                        KillProcessAndChildren(EasyHook.RemoteHooking.GetCurrentProcessId());
                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            // now call the original API...
            return NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, out ProcessInformation, ProcessInformationLength, out ReturnLength);
        }
    
        #endregion

        #region NtQueryAttributesFile Hook (Locky)
        //delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate int NtQueryAttributesFile_Delegate(
             IntPtr ObjectAttributes,
             out IntPtr FileInformation);

        //original
        [DllImport("ntdll.dll",
    CharSet = CharSet.Unicode,
    SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern int NtQueryAttributesFile(
             IntPtr ObjectAttributes,
             out IntPtr FileInformation);

        //hooked
        int NtQueryAttributesFile_Hook(
           IntPtr ObjectAttributes,
           out IntPtr FileInformation)
        {
            //Do the redirected commands..
            try
            {
                LockyCounter++;
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        // Add message to send to FileMonitor
                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: NtQueryAttributesFile COUNT:{2}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), LockyCounter));
                    }
                    if (LockyCounter >= 8000)
                    {
                        MessageBox.Show("Malicious behaviour detected, press OK to terminate", "BrainFreeze", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                        _server.ReportMessage("Criteria met for Locky. Killing hooked process... \n<Press any key to exit>");
                        KillProcessAndChildren(EasyHook.RemoteHooking.GetCurrentProcessId());
                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            // now call the original API...
            return NtQueryAttributesFile(ObjectAttributes, out FileInformation);
        }
        #endregion

        #region NtQueryInformationFile Hook (Vipasana)
        //delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate int NtQueryInformationFile_Delegate(
             IntPtr FileHandle,
             IntPtr IoStatusBlock,
             IntPtr FileInformation,
             uint Length,
             IntPtr FileInformationClass);

        //original
        [DllImport("ntdll.dll",
    CharSet = CharSet.Unicode,
    SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern int NtQueryInformationFile(
             IntPtr FileHandle,
             IntPtr IoStatusBlock,
             IntPtr FileInformation,
             uint Length,
             IntPtr FileInformationClass);

        //hooked
        int NtQueryInformationFile_Hook(
             IntPtr FileHandle,
             IntPtr IoStatusBlock,
             IntPtr FileInformation,
             uint Length,
             IntPtr FileInformationClass)
        {
            //Do the redirected commands..
            try
            {
                VipasanaCounter++;
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        // Add message to send to FileMonitor
                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: NtQueryInformationFile COUNT:{2}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), VipasanaCounter));
                    }
                    if (VipasanaCounter >= 265686)// && VipasanaCounter2 >= 132843 && VipasanaCounter3 >= 132843 && VipasanaCounter4 >= 132843)
                    {
                        _server.ReportMessage("Criteria Met for Vipasana. Killing hooked process... \n<Press any key to exit>");
                        KillProcessAndChildren(EasyHook.RemoteHooking.GetCurrentProcessId());
                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            // now call the original API...
            return NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation,Length,FileInformationClass);
        }
        #endregion

        #region NtSetInformationFile (Vipasana)
        //delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
    CharSet = CharSet.Unicode,
    SetLastError = true)]
        delegate int NtSetInformationFile_Delegate(
            IntPtr FileHandle,
            IntPtr IoStatusBlock,
            IntPtr FileInformation,
            uint Length,
            IntPtr FileInformationClass);
        //original
        [DllImport("ntdll.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern int NtSetInformationFile(
            IntPtr FileHandle,
            IntPtr IoStatusBlock,
            IntPtr FileInformation,
            uint Length,
            IntPtr FileInformationClass);
        //hook
        int NtSetInformationFile_Hook(
            IntPtr FileHandle,
            IntPtr IoStatusBlock,
            IntPtr FileInformation,
            uint Length,
            IntPtr FileInformationClass)
        { 
            //Do the redirected commands..
            try
            {
                VipasanaCounter2++;
                lock (this._messageQueue)
                {
            if (this._messageQueue.Count < 1000)
            {
                // Add message to send to FileMonitor
                this._messageQueue.Enqueue(
                    string.Format("[{0}:{1}]: NtSetInformationFile COUNT:{2}",
                    EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), VipasanaCounter2));
            }
                if (VipasanaCounter >= 265686 && VipasanaCounter2 >= 132843 && VipasanaCounter3 >= 132843 && VipasanaCounter4 >= 132843)
                {
                _server.ReportMessage("Criteria Met for Vipasana(NtSetInformationFile). Killing hooked process... \n<Press any key to exit>");
                KillProcessAndChildren(EasyHook.RemoteHooking.GetCurrentProcessId());
            }
        }
        }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            // now call the original API...
            return NtSetInformationFile(FileHandle,IoStatusBlock,FileInformation,Length,FileInformationClass);
    }
        #endregion

        #region NtReadFile(vipasana)
        //delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
    CharSet = CharSet.Unicode,
    SetLastError = true)]
        delegate int NtReadFile_Delegate(
            IntPtr Handle,
            IntPtr Event,
            IntPtr ApcRouting,
            IntPtr ApcContext,
            out IntPtr IoStatusBlock,
            out IntPtr Buffer,
            uint Length,
            IntPtr ByteOffset,
            IntPtr Key);
        //original
        [DllImport("ntdll.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern int NtReadFile(
            IntPtr Handle,
            IntPtr Event,
            IntPtr ApcRouting,
            IntPtr ApcContext,
            out IntPtr IoStatusBlock,
            out IntPtr Buffer,
            uint Length,
            IntPtr ByteOffset,
            IntPtr Key);
        //hook
        int NtReadFile_Hook(
            IntPtr Handle,
            IntPtr Event,
            IntPtr ApcRouting,
            IntPtr ApcContext,
            out IntPtr IoStatusBlock,
            out IntPtr Buffer,
            uint Length,
            IntPtr ByteOffset,
            IntPtr Key)
        { 
            //Do the redirected commands..
            try
            {
                VipasanaCounter3++;
                lock (this._messageQueue)
                {
            if (this._messageQueue.Count < 1000)
            {
                // Add message to send to FileMonitor
                this._messageQueue.Enqueue(
                    string.Format("[{0}:{1}]: NtReadFile COUNT:{2}",
                    EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), VipasanaCounter3));
            }
                if (VipasanaCounter >= 265686 && VipasanaCounter2 >= 132843 && VipasanaCounter3 >= 132843 && VipasanaCounter4 >= 132843)
                {
                _server.ReportMessage("Criteria Met for Vipasana(NtReadFile). Killing hooked process... \n<Press any key to exit>");
                KillProcessAndChildren(EasyHook.RemoteHooking.GetCurrentProcessId());
            }
        }
        }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            // now call the original API...
            return NtReadFile(Handle,Event, ApcRouting, ApcContext,out IoStatusBlock,out Buffer,Length,ByteOffset, Key);
    }
        #endregion

        #region NtWritefile(vipasana)
        //delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
        CharSet = CharSet.Unicode,
        SetLastError = true)]
        delegate int NtWriteFile_Delegate(
            IntPtr Handle,
            IntPtr Event,
            IntPtr ApcRouting,
            IntPtr ApcContext,
            out IntPtr IoStatusBlock,
            out IntPtr Buffer,
            uint Length,
            IntPtr ByteOffset,
            IntPtr Key);
        //original
        [DllImport("ntdll.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern int NtWriteFile(
            IntPtr Handle,
            IntPtr Event,
            IntPtr ApcRouting,
            IntPtr ApcContext,
            out IntPtr IoStatusBlock,
            out IntPtr Buffer,
            uint Length,
            IntPtr ByteOffset,
            IntPtr Key);
        //hook
        int NtWriteFile_Hook(
            IntPtr Handle,
            IntPtr Event,
            IntPtr ApcRouting,
            IntPtr ApcContext,
            out IntPtr IoStatusBlock,
            out IntPtr Buffer,
            uint Length,
            IntPtr ByteOffset,
            IntPtr Key)
        {
            //Do the redirected commands..
            try
            {
                VipasanaCounter4++;
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        // Add message to send to FileMonitor
                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: NtWriteFile COUNT:{2}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), VipasanaCounter4));
                    }
                    if (VipasanaCounter >= 265686 && VipasanaCounter2 >= 132843 && VipasanaCounter3 >= 132843 && VipasanaCounter4 >= 132843)
                    {
                        _server.ReportMessage("Criteria Met for Vipasana(NtWriteFile). Killing hooked process... \n<Press any key to exit>");
                        KillProcessAndChildren(EasyHook.RemoteHooking.GetCurrentProcessId());
                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            // now call the original API...
            return NtWriteFile(Handle, Event, ApcRouting, ApcContext, out IoStatusBlock, out Buffer, Length, ByteOffset, Key);
        }
        #endregion
        
        #region NtWaitForSingleObject Hook (Cerber)
        //delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate int NtWaitForSingleObject_Delegate(
             IntPtr Handle,
             bool Alertable,
             IntPtr Timeout);

        //original
        [DllImport("ntdll.dll",
    CharSet = CharSet.Unicode,
    SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern int NtWaitForSingleObject(
             IntPtr Handle,
             bool Alertable,
             IntPtr Timeout);

        //hooked
        int NtWaitForSingleObject_Hook(
             IntPtr Handle,
             bool Alertable,
             IntPtr Timeout)
        {
            //Do the redirected commands..
            try
            {
                CerberCounter++;
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        // Add message to send to FileMonitor
                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: NtWaitForSingleObject COUNT:{2}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), CerberCounter));
                    }
                    if (CerberCounter >= 7331)
                    {
                        //MessageBox.Show("Malicious behaviour detected, press OK to terminate", "BrainFreeze", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                        _server.ReportMessage(string.Format("Critera met for Cerber. (value: {0}) Killing hooked process... \n<Press any key to exit>",CerberCounter));
                        KillProcessAndChildren(EasyHook.RemoteHooking.GetCurrentProcessId());
                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            // now call the original API...
            return NtWaitForSingleObject(Handle, Alertable,Timeout);
        }
        #endregion

        #region CreateFileW Hook

        /// <summary>
        /// The CreateFile delegate, this is needed to create a delegate of our hook function <see cref="CreateFile_Hook(string, uint, uint, IntPtr, uint, uint, IntPtr)"/>.
        /// </summary>
        /// <param name="filename"></param>
        /// <param name="desiredAccess"></param>
        /// <param name="shareMode"></param>
        /// <param name="securityAttributes"></param>
        /// <param name="creationDisposition"></param>
        /// <param name="flagsAndAttributes"></param>
        /// <param name="templateFile"></param>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
                    CharSet = CharSet.Unicode,
                    SetLastError = true)]
        delegate IntPtr CreateFile_Delegate(
                    String filename,
                    UInt32 desiredAccess,
                    UInt32 shareMode,
                    IntPtr securityAttributes,
                    UInt32 creationDisposition,
                    UInt32 flagsAndAttributes,
                    IntPtr templateFile);

        /// <summary>
        /// Using P/Invoke to call original method.
        /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx
        /// </summary>
        /// <param name="filename"></param>
        /// <param name="desiredAccess"></param>
        /// <param name="shareMode"></param>
        /// <param name="securityAttributes"></param>
        /// <param name="creationDisposition"></param>
        /// <param name="flagsAndAttributes"></param>
        /// <param name="templateFile"></param>
        /// <returns></returns>
        [DllImport("kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr CreateFileW(
            String filename,
            UInt32 desiredAccess,
            UInt32 shareMode,
            IntPtr securityAttributes,
            UInt32 creationDisposition,
            UInt32 flagsAndAttributes,
            IntPtr templateFile);

        /// <summary>
        /// The CreateFile hook function. This will be called instead of the original CreateFile once hooked.
        /// </summary>
        /// <param name="filename"></param>
        /// <param name="desiredAccess"></param>
        /// <param name="shareMode"></param>
        /// <param name="securityAttributes"></param>
        /// <param name="creationDisposition"></param>
        /// <param name="flagsAndAttributes"></param>
        /// <param name="templateFile"></param>
        /// <returns></returns>
        IntPtr CreateFile_Hook(
            String filename,
            UInt32 desiredAccess,
            UInt32 shareMode,
            IntPtr securityAttributes,
            UInt32 creationDisposition,
            UInt32 flagsAndAttributes,
            IntPtr templateFile)
        {
                try
                {
                    lock (this._messageQueue)
                    {
                        if (this._messageQueue.Count < 1000)
                        {
                            string mode = string.Empty;
                            switch (creationDisposition)
                            {
                                case 1:
                                    mode = "CREATE_NEW";
                                    break;
                                case 2:
                                    mode = "CREATE_ALWAYS";
                                    break;
                                case 3:
                                    mode = "OPEN_ALWAYS";
                                    break;
                                case 4:
                                    mode = "OPEN_EXISTING";
                                    break;
                                case 5:
                                    mode = "TRUNCATE_EXISTING";
                                    break;
                            }

                            // Add message to send to FileMonitor
                            this._messageQueue.Enqueue(
                                string.Format("[{0}:{1}]: CREATE ({2}) \"{3}\" ",
                                EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId()
                                , mode, filename));
                        }
                    }
                }
                catch
                {
                    // swallow exceptions so that any issues caused by this code do not crash target process
                }
            // now call the original API...
            return CreateFileW(
                filename,
                desiredAccess,
                shareMode,
                securityAttributes,
                creationDisposition,
                flagsAndAttributes,
                templateFile);
        }

        #endregion

        #region ReadFile Hook

        /// <summary>
        /// The ReadFile delegate, this is needed to create a delegate of our hook function <see cref="ReadFile_Hook(IntPtr, IntPtr, uint, out uint, IntPtr)"/>.
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToRead"></param>
        /// <param name="lpNumberOfBytesRead"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool ReadFile_Delegate(
            IntPtr hFile,
            IntPtr lpBuffer,
            uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        /// <summary>
        /// Using P/Invoke to call the orginal function
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToRead"></param>
        /// <param name="lpNumberOfBytesRead"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool ReadFile(
            IntPtr hFile, 
            IntPtr lpBuffer,
            uint nNumberOfBytesToRead, 
            out uint lpNumberOfBytesRead, 
            IntPtr lpOverlapped);

        /// <summary>
        /// The ReadFile hook function. This will be called instead of the original ReadFile once hooked.
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToRead"></param>
        /// <param name="lpNumberOfBytesRead"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        bool ReadFile_Hook(
            IntPtr hFile,
            IntPtr lpBuffer,
            uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead,
            IntPtr lpOverlapped)
        {
            bool result = false;
            lpNumberOfBytesRead = 0;

            // Call original first so we have a value for lpNumberOfBytesRead
            result = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, out lpNumberOfBytesRead, lpOverlapped);
                try
                {
                    lock (this._messageQueue)
                    {
                        if (this._messageQueue.Count < 1000)
                        {
                            // Retrieve filename from the file handle
                            StringBuilder filename = new StringBuilder(255);
                            GetFinalPathNameByHandle(hFile, filename, 255, 0);

                            // Add message to send to FileMonitor
                            this._messageQueue.Enqueue(
                                string.Format("[{0}:{1}]: READ ({2} bytes) \"{3}\"",
                                EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId()
                                , lpNumberOfBytesRead, filename));
                        }
                    }
                }
                catch
                {
                    // swallow exceptions so that any issues caused by this code do not crash target process
                }
            
            return result;
        }

        #endregion

        #region WriteFile Hook

        /// <summary>
        /// The WriteFile delegate, this is needed to create a delegate of our hook function <see cref="WriteFile_Hook(IntPtr, IntPtr, uint, out uint, IntPtr)"/>.
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToWrite"></param>
        /// <param name="lpNumberOfBytesWritten"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        delegate bool WriteFile_Delegate(
            IntPtr hFile,
            IntPtr lpBuffer,
            uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten,
            IntPtr lpOverlapped);

        /// <summary>
        /// Using P/Invoke to call original WriteFile method
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToWrite"></param>
        /// <param name="lpNumberOfBytesWritten"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool WriteFile(
            IntPtr hFile,
            IntPtr lpBuffer,
            uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten,
            IntPtr lpOverlapped);

        /// <summary>
        /// The WriteFile hook function. This will be called instead of the original WriteFile once hooked.
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToWrite"></param>
        /// <param name="lpNumberOfBytesWritten"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        bool WriteFile_Hook(
            IntPtr hFile,
            IntPtr lpBuffer,
            uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten,
            IntPtr lpOverlapped)
        {
            bool result = false;
                // Call original first so we get lpNumberOfBytesWritten
                result = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, out lpNumberOfBytesWritten, lpOverlapped);
                try
                {
                    lock (this._messageQueue)
                    {
                        if (this._messageQueue.Count < 1000)
                        {
                            // Retrieve filename from the file handle
                            StringBuilder filename = new StringBuilder(255);
                            GetFinalPathNameByHandle(hFile, filename, 255, 0);

                            // Add message to send to FileMonitor
                            this._messageQueue.Enqueue(
                                string.Format("[{0}:{1}]: WRITE ({2} bytes) \"{3}\"",
                                EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId()
                                , lpNumberOfBytesWritten, filename));
                        }
                    }
                }
                catch
                {
                    // swallow exceptions so that any issues caused by this code do not crash target process
                }
            return result;
        }

        #endregion
    }
}
