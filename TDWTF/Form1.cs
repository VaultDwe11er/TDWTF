using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

namespace TDWTF
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();

            int il = GetProcessIntegrityLevel();

            button1.Enabled = !(il == (int)NativeMethod.SECURITY_MANDATORY_MEDIUM_RID);
        }

        private void button1_Click(object sender, EventArgs e)
        {
            button1.Enabled = false;
            button2.Enabled = false;
            new Thread(GetMissingLikes).Start();
        }

        private void GetMissingLikes()
        {
            int i = int.Parse(textBox1.Text);
            bool found = false;
            int postCnt = int.MaxValue;

            CookieContainer cookies = GetUriCookieContainer(webBrowser1.Url);

            WebClient wc = new WebClient();

            wc.Headers.Add(HttpRequestHeader.Cookie, cookies.GetCookieHeader(webBrowser1.Url));

            String patMissingLike = "\"id\":2,\"count\":\\d*,\"hidden\":false,\"can_act\":true";
            String patPostCnt = "(\"highest_post_number\":)(\\d*)(?!.*\"highest_post_number\":)";
            String patLastPost = "(\"post_number\":)(\\d*)(?!.*\"post_number\":)";

            Regex reMissingLike = new Regex(patMissingLike);
            Regex rePostCnt = new Regex(patPostCnt);
            Regex reLastPost = new Regex(patLastPost);

            while (!found && i < postCnt)
            {
                toolStripStatusLabel1.Text = "Processing (i = " + i.ToString() + ")...";
                this.Refresh();
                this.Update();

                string json;

                try
                {
                    json = wc.DownloadString(@"http://what.thedailywtf.com/t/1000/" + i.ToString() + ".json");
                }
                catch (WebException)
                {
                    toolStripStatusLabel1.Text = "Timed out (i = " + i.ToString() + ")";
                    button1.Enabled = true;
                    button2.Enabled = true;
                    return;
                }

                found = reMissingLike.Match(json).Success;
                //found = true;

                postCnt = int.Parse(rePostCnt.Match(json).Groups[2].Value);
                i = int.Parse(reLastPost.Match(json).Groups[2].Value) + 1;
            }

            toolStripStatusLabel1.Text = found ? "Done. Found at " + i : "No likes missed (postCnt = " + postCnt + ")";

            button1.Enabled = true;
            button2.Enabled = true;
        }

        private void button2_Click(object sender, EventArgs e)
        {
            CreateLowIntegrityProcess(Application.ExecutablePath);
        }

        internal void CreateLowIntegrityProcess(string commandLine)
        {
            SafeTokenHandle hToken = null;
            SafeTokenHandle hNewToken = null;
            IntPtr pIntegritySid = IntPtr.Zero;
            int cbTokenInfo = 0;
            IntPtr pTokenInfo = IntPtr.Zero;
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            try
            {
                // Open the primary access token of the process.
                if (!NativeMethod.OpenProcessToken(Process.GetCurrentProcess().Handle,
                    NativeMethod.TOKEN_DUPLICATE | NativeMethod.TOKEN_ADJUST_DEFAULT |
                    NativeMethod.TOKEN_QUERY | NativeMethod.TOKEN_ASSIGN_PRIMARY,
                    out hToken))
                {
                    throw new Win32Exception();
                }

                // Duplicate the primary token of the current process.
                if (!NativeMethod.DuplicateTokenEx(hToken, 0, IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    TOKEN_TYPE.TokenPrimary, out hNewToken))
                {
                    throw new Win32Exception();
                }

                // Create the low integrity SID.
                if (!NativeMethod.AllocateAndInitializeSid(
                    ref NativeMethod.SECURITY_MANDATORY_LABEL_AUTHORITY, 1,
                    NativeMethod.SECURITY_MANDATORY_LOW_RID,
                    0, 0, 0, 0, 0, 0, 0, out pIntegritySid))
                {
                    throw new Win32Exception();
                }

                TOKEN_MANDATORY_LABEL tml;
                tml.Label.Attributes = NativeMethod.SE_GROUP_INTEGRITY;
                tml.Label.Sid = pIntegritySid;

                // Marshal the TOKEN_MANDATORY_LABEL struct to the native memory.
                cbTokenInfo = Marshal.SizeOf(tml);
                pTokenInfo = Marshal.AllocHGlobal(cbTokenInfo);
                Marshal.StructureToPtr(tml, pTokenInfo, false);

                // Set the integrity level in the access token to low.
                if (!NativeMethod.SetTokenInformation(hNewToken,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pTokenInfo,
                    cbTokenInfo + NativeMethod.GetLengthSid(pIntegritySid)))
                {
                    throw new Win32Exception();
                }

                // Create the new process at the Low integrity level.
                si.cb = Marshal.SizeOf(si);
                if (!NativeMethod.CreateProcessAsUser(hNewToken, null, commandLine,
                    IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si,
                    out pi))
                {
                    throw new Win32Exception();
                }
            }
            finally
            {
                // Centralized cleanup for all allocated resources. 
                if (hToken != null)
                {
                    hToken.Close();
                    hToken = null;
                }
                if (hNewToken != null)
                {
                    hNewToken.Close();
                    hNewToken = null;
                }
                if (pIntegritySid != IntPtr.Zero)
                {
                    NativeMethod.FreeSid(pIntegritySid);
                    pIntegritySid = IntPtr.Zero;
                }
                if (pTokenInfo != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pTokenInfo);
                    pTokenInfo = IntPtr.Zero;
                    cbTokenInfo = 0;
                }
                if (pi.hProcess != IntPtr.Zero)
                {
                    NativeMethod.CloseHandle(pi.hProcess);
                    pi.hProcess = IntPtr.Zero;
                }
                if (pi.hThread != IntPtr.Zero)
                {
                    NativeMethod.CloseHandle(pi.hThread);
                    pi.hThread = IntPtr.Zero;
                }
            }
        }
        
        internal int GetProcessIntegrityLevel()
        {
            int IL = -1;
            SafeTokenHandle hToken = null;
            int cbTokenIL = 0;
            IntPtr pTokenIL = IntPtr.Zero;

            try
            {
                // Open the access token of the current process with TOKEN_QUERY.
                if (!NativeMethod.OpenProcessToken(Process.GetCurrentProcess().Handle,
                    NativeMethod.TOKEN_QUERY, out hToken))
                {
                    throw new Win32Exception();
                }

                // Then we must query the size of the integrity level information 
                // associated with the token. Note that we expect GetTokenInformation 
                // to return false with the ERROR_INSUFFICIENT_BUFFER error code 
                // because we've given it a null buffer. On exit cbTokenIL will tell 
                // the size of the group information.
                if (!NativeMethod.GetTokenInformation(hToken,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, 0,
                    out cbTokenIL))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error != NativeMethod.ERROR_INSUFFICIENT_BUFFER)
                    {
                        // When the process is run on operating systems prior to 
                        // Windows Vista, GetTokenInformation returns false with the 
                        // ERROR_INVALID_PARAMETER error code because 
                        // TokenIntegrityLevel is not supported on those OS's.
                        throw new Win32Exception(error);
                    }
                }

                // Now we allocate a buffer for the integrity level information.
                pTokenIL = Marshal.AllocHGlobal(cbTokenIL);
                if (pTokenIL == IntPtr.Zero)
                {
                    throw new Win32Exception();
                }

                // Now we ask for the integrity level information again. This may fail 
                // if an administrator has added this account to an additional group 
                // between our first call to GetTokenInformation and this one.
                if (!NativeMethod.GetTokenInformation(hToken,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pTokenIL, cbTokenIL,
                    out cbTokenIL))
                {
                    throw new Win32Exception();
                }

                // Marshal the TOKEN_MANDATORY_LABEL struct from native to .NET object.
                TOKEN_MANDATORY_LABEL tokenIL = (TOKEN_MANDATORY_LABEL)
                    Marshal.PtrToStructure(pTokenIL, typeof(TOKEN_MANDATORY_LABEL));

                // Integrity Level SIDs are in the form of S-1-16-0xXXXX. (e.g. 
                // S-1-16-0x1000 stands for low integrity level SID). There is one 
                // and only one subauthority.
                IntPtr pIL = NativeMethod.GetSidSubAuthority(tokenIL.Label.Sid, 0);
                IL = Marshal.ReadInt32(pIL);
            }
            finally
            {
                // Centralized cleanup for all allocated resources. 
                if (hToken != null)
                {
                    hToken.Close();
                    hToken = null;
                }
                if (pTokenIL != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pTokenIL);
                    pTokenIL = IntPtr.Zero;
                    cbTokenIL = 0;
                }
            }

            return IL;
        }

        [DllImport("wininet.dll", SetLastError = true)]
        public static extern bool InternetGetCookieEx(
            string url,
            string cookieName,
            StringBuilder cookieData,
            ref int size,
            Int32 dwFlags,
            IntPtr lpReserved);

        private const Int32 InternetCookieHttponly = 0x2000;

        /// <summary>
        /// Gets the URI cookie container.
        /// </summary>
        /// <param name="uri">The URI.</param>
        /// <returns></returns>
        public static CookieContainer GetUriCookieContainer(Uri uri)
        {
            CookieContainer cookies = null;
            // Determine the size of the cookie
            int datasize = 8192 * 16;
            StringBuilder cookieData = new StringBuilder(datasize);
            if (!InternetGetCookieEx(uri.ToString(), null, cookieData, ref datasize, InternetCookieHttponly, IntPtr.Zero))
            {
                if (datasize < 0)
                    return null;
                // Allocate stringbuilder large enough to hold the cookie
                cookieData = new StringBuilder(datasize);
                if (!InternetGetCookieEx(
                    uri.ToString(),
                    null, cookieData,
                    ref datasize,
                    InternetCookieHttponly,
                    IntPtr.Zero))
                    return null;
            }
            if (cookieData.Length > 0)
            {
                cookies = new CookieContainer();
                cookies.SetCookies(uri, cookieData.ToString().Replace(';', ','));
            }
            return cookies;
        }
    }
    internal class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeTokenHandle()
            : base(true)
        {
        }

        internal SafeTokenHandle(IntPtr handle)
            : base(true)
        {
            base.SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return NativeMethod.CloseHandle(base.handle);
        }
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    internal class NativeMethod
    {
        // Token Specific Access Rights

        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED |
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE |
            TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES |
            TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);


        public const Int32 ERROR_INSUFFICIENT_BUFFER = 122;


        // Integrity Levels

        public static SID_IDENTIFIER_AUTHORITY SECURITY_MANDATORY_LABEL_AUTHORITY =
            new SID_IDENTIFIER_AUTHORITY(new byte[] { 0, 0, 0, 0, 0, 16 });
        public const Int32 SECURITY_MANDATORY_UNTRUSTED_RID = 0x00000000;
        public const Int32 SECURITY_MANDATORY_LOW_RID = 0x00001000;
        public const Int32 SECURITY_MANDATORY_MEDIUM_RID = 0x00002000;
        public const Int32 SECURITY_MANDATORY_HIGH_RID = 0x00003000;
        public const Int32 SECURITY_MANDATORY_SYSTEM_RID = 0x00004000;


        // Group related SID Attributes

        public const UInt32 SE_GROUP_MANDATORY = 0x00000001;
        public const UInt32 SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002;
        public const UInt32 SE_GROUP_ENABLED = 0x00000004;
        public const UInt32 SE_GROUP_OWNER = 0x00000008;
        public const UInt32 SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010;
        public const UInt32 SE_GROUP_INTEGRITY = 0x00000020;
        public const UInt32 SE_GROUP_INTEGRITY_ENABLED = 0x00000040;
        public const UInt32 SE_GROUP_LOGON_ID = 0xC0000000;
        public const UInt32 SE_GROUP_RESOURCE = 0x20000000;
        public const UInt32 SE_GROUP_VALID_ATTRIBUTES = (SE_GROUP_MANDATORY |
            SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED | SE_GROUP_OWNER |
            SE_GROUP_USE_FOR_DENY_ONLY | SE_GROUP_LOGON_ID | SE_GROUP_RESOURCE |
            SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED);


        /// <summary>
        /// The function opens the access token associated with a process.
        /// </summary>
        /// <param name="hProcess">
        /// A handle to the process whose access token is opened.
        /// </param>
        /// <param name="desiredAccess">
        /// Specifies an access mask that specifies the requested types of 
        /// access to the access token. 
        /// </param>
        /// <param name="hToken">
        /// Outputs a handle that identifies the newly opened access token 
        /// when the function returns.
        /// </param>
        /// <returns></returns>
        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr hProcess,
            UInt32 desiredAccess,
            out SafeTokenHandle hToken);


        /// <summary>
        /// The DuplicateTokenEx function creates a new access token that 
        /// duplicates an existing token. This function can create either a 
        /// primary token or an impersonation token.
        /// </summary>
        /// <param name="hExistingToken">
        /// A handle to an access token opened with TOKEN_DUPLICATE access.
        /// </param>
        /// <param name="desiredAccess">
        /// Specifies the requested access rights for the new token.
        /// </param>
        /// <param name="pTokenAttributes">
        /// A pointer to a SECURITY_ATTRIBUTES structure that specifies a 
        /// security descriptor for the new token and determines whether 
        /// child processes can inherit the token. If lpTokenAttributes is 
        /// NULL, the token gets a default security descriptor and the handle 
        /// cannot be inherited. 
        /// </param>
        /// <param name="ImpersonationLevel">
        /// Specifies the impersonation level of the new token.
        /// </param>
        /// <param name="TokenType">
        /// TokenPrimary - The new token is a primary token that you can use 
        /// in the CreateProcessAsUser function.
        /// TokenImpersonation - The new token is an impersonation token.
        /// </param>
        /// <param name="hNewToken">
        /// Receives the new token.
        /// </param>
        /// <returns></returns>
        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateTokenEx(
            SafeTokenHandle hExistingToken,
            UInt32 desiredAccess,
            IntPtr pTokenAttributes,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            TOKEN_TYPE TokenType,
            out SafeTokenHandle hNewToken);


        /// <summary>
        /// The function retrieves a specified type of information about an 
        /// access token. The calling process must have appropriate access 
        /// rights to obtain the information.
        /// </summary>
        /// <param name="hToken">
        /// A handle to an access token from which information is retrieved.
        /// </param>
        /// <param name="tokenInfoClass">
        /// Specifies a value from the TOKEN_INFORMATION_CLASS enumerated 
        /// type to identify the type of information the function retrieves.
        /// </param>
        /// <param name="pTokenInfo">
        /// A pointer to a buffer the function fills with the requested 
        /// information.
        /// </param>
        /// <param name="tokenInfoLength">
        /// Specifies the size, in bytes, of the buffer pointed to by the 
        /// TokenInformation parameter. 
        /// </param>
        /// <param name="returnLength">
        /// A pointer to a variable that receives the number of bytes needed 
        /// for the buffer pointed to by the TokenInformation parameter. 
        /// </param>
        /// <returns></returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(
            SafeTokenHandle hToken,
            TOKEN_INFORMATION_CLASS tokenInfoClass,
            IntPtr pTokenInfo,
            Int32 tokenInfoLength,
            out Int32 returnLength);


        /// <summary>
        /// The function sets various types of information for a specified 
        /// access token. The information that this function sets replaces 
        /// existing information. The calling process must have appropriate 
        /// access rights to set the information.
        /// </summary>
        /// <param name="hToken">
        /// A handle to the access token for which information is to be set.
        /// </param>
        /// <param name="tokenInfoClass">
        /// A value from the TOKEN_INFORMATION_CLASS enumerated type that 
        /// identifies the type of information the function sets. 
        /// </param>
        /// <param name="pTokenInfo">
        /// A pointer to a buffer that contains the information set in the 
        /// access token. 
        /// </param>
        /// <param name="tokenInfoLength">
        /// Specifies the length, in bytes, of the buffer pointed to by 
        /// TokenInformation.
        /// </param>
        /// <returns></returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetTokenInformation(
            SafeTokenHandle hToken,
            TOKEN_INFORMATION_CLASS tokenInfoClass,
            IntPtr pTokenInfo,
            Int32 tokenInfoLength);


        /// <summary>
        /// The function returns a pointer to a specified subauthority in a 
        /// security identifier (SID). The subauthority value is a relative 
        /// identifier (RID).
        /// </summary>
        /// <param name="pSid">
        /// A pointer to the SID structure from which a pointer to a 
        /// subauthority is to be returned.
        /// </param>
        /// <param name="nSubAuthority">
        /// Specifies an index value identifying the subauthority array 
        /// element whose address the function will return.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is a pointer to the 
        /// specified SID subauthority. To get extended error information, 
        /// call GetLastError. If the function fails, the return value is 
        /// undefined. The function fails if the specified SID structure is 
        /// not valid or if the index value specified by the nSubAuthority 
        /// parameter is out of bounds.
        /// </returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr GetSidSubAuthority(
            IntPtr pSid,
            UInt32 nSubAuthority);


        /// <summary>
        /// The AllocateAndInitializeSid function allocates and initializes a 
        /// security identifier (SID) with up to eight subauthorities.
        /// </summary>
        /// <param name="pIdentifierAuthority">
        /// A reference of a SID_IDENTIFIER_AUTHORITY structure. This 
        /// structure provides the top-level identifier authority value to 
        /// set in the SID.
        /// </param>
        /// <param name="nSubAuthorityCount">
        /// Specifies the number of subauthorities to place in the SID. 
        /// </param>
        /// <param name="dwSubAuthority0">
        /// Subauthority value to place in the SID.
        /// </param>
        /// <param name="dwSubAuthority1">
        /// Subauthority value to place in the SID.
        /// </param>
        /// <param name="dwSubAuthority2">
        /// Subauthority value to place in the SID.
        /// </param>
        /// <param name="dwSubAuthority3">
        /// Subauthority value to place in the SID.
        /// </param>
        /// <param name="dwSubAuthority4">
        /// Subauthority value to place in the SID.
        /// </param>
        /// <param name="dwSubAuthority5">
        /// Subauthority value to place in the SID.
        /// </param>
        /// <param name="dwSubAuthority6">
        /// Subauthority value to place in the SID.
        /// </param>
        /// <param name="dwSubAuthority7">
        /// Subauthority value to place in the SID.
        /// </param>
        /// <param name="pSid">
        /// Outputs the allocated and initialized SID structure.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is true. If the 
        /// function fails, the return value is false. To get extended error 
        /// information, call GetLastError.
        /// </returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AllocateAndInitializeSid(
            ref SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
            byte nSubAuthorityCount,
            int dwSubAuthority0, int dwSubAuthority1,
            int dwSubAuthority2, int dwSubAuthority3,
            int dwSubAuthority4, int dwSubAuthority5,
            int dwSubAuthority6, int dwSubAuthority7,
            out IntPtr pSid);


        /// <summary>
        /// The FreeSid function frees a security identifier (SID) previously 
        /// allocated by using the AllocateAndInitializeSid function.
        /// </summary>
        /// <param name="pSid">
        /// A pointer to the SID structure to free.
        /// </param>
        /// <returns>
        /// If the function succeeds, the function returns NULL. If the 
        /// function fails, it returns a pointer to the SID structure 
        /// represented by the pSid parameter.
        /// </returns>
        [DllImport("advapi32.dll")]
        public static extern IntPtr FreeSid(IntPtr pSid);


        /// <summary>
        /// The function returns the length, in bytes, of a valid security 
        /// identifier (SID).
        /// </summary>
        /// <param name="pSID">
        /// A pointer to the SID structure whose length is returned. 
        /// </param>
        /// <returns>
        /// If the SID structure is valid, the return value is the length, in 
        /// bytes, of the SID structure.
        /// </returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int GetLengthSid(IntPtr pSID);


        /// <summary>
        /// Creates a new process and its primary thread. The new process 
        /// runs in the security context of the user represented by the 
        /// specified token.
        /// </summary>
        /// <param name="hToken">
        /// A handle to the primary token that represents a user. 
        /// </param>
        /// <param name="applicationName">
        /// The name of the module to be executed.
        /// </param>
        /// <param name="commandLine">
        /// The command line to be executed. The maximum length of this 
        /// string is 32K characters. 
        /// </param>
        /// <param name="pProcessAttributes">
        /// A pointer to a SECURITY_ATTRIBUTES structure that specifies a 
        /// security descriptor for the new process object and determines 
        /// whether child processes can inherit the returned handle to the 
        /// process.
        /// </param>
        /// <param name="pThreadAttributes">
        /// A pointer to a SECURITY_ATTRIBUTES structure that specifies a 
        /// security descriptor for the new thread object and determines 
        /// whether child processes can inherit the returned handle to the 
        /// thread.
        /// </param>
        /// <param name="bInheritHandles">
        /// If this parameter is true, each inheritable handle in the calling 
        /// process is inherited by the new process. If the parameter is 
        /// false, the handles are not inherited. 
        /// </param>
        /// <param name="dwCreationFlags">
        /// The flags that control the priority class and the creation of the 
        /// process.
        /// </param>
        /// <param name="pEnvironment">
        /// A pointer to an environment block for the new process. 
        /// </param>
        /// <param name="currentDirectory">
        /// The full path to the current directory for the process. 
        /// </param>
        /// <param name="startupInfo">
        /// References a STARTUPINFO structure.
        /// </param>
        /// <param name="processInformation">
        /// Outputs a PROCESS_INFORMATION structure that receives 
        /// identification information about the new process. 
        /// </param>
        /// <returns></returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessAsUser(
            SafeTokenHandle hToken,
            string applicationName,
            string commandLine,
            IntPtr pProcessAttributes,
            IntPtr pThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr pEnvironment,
            string currentDirectory,
            ref STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);


        /// <summary>
        /// Closes an open object handle.
        /// </summary>
        /// <param name="handle">A valid handle to an open object.</param>
        /// <returns></returns>
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);
    }

    internal enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    internal enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public UInt32 Attributes;
    }

    internal enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        MaxTokenInfoClass
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_IDENTIFIER_AUTHORITY
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6,
            ArraySubType = UnmanagedType.I1)]
        public byte[] Value;

        public SID_IDENTIFIER_AUTHORITY(byte[] value)
        {
            this.Value = value;
        }
    }
}