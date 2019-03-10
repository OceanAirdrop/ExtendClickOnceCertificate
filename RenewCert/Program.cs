using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace NewRenewCert
{
    class Program
    {

        const int YearsToExtend = 105;

        // ReSharper disable InconsistentNaming

        //static void ErrorExit(string lpszFunction)
        //{
        //    int dw = Marshal.GetLastWin32Error();
        //    var ex = new System.ComponentModel.Win32Exception(dw);

        //    Console.WriteLine("{0} failed with error {1}: {2}\nExiting", lpszFunction, dw, ex.Message);
        //    if (Debugger.IsAttached) Console.ReadKey(true);

        //    Environment.Exit(dw);
        //}

        static void ReadPFXFile(string fileName, out Crypt.CRYPT_DATA_BLOB pPFX)
        {
            SafeFileHandle hCertFile;
            int cbRead = 0;
            int dwFileSize = 0; // dwFileSizeHi = 0;

            hCertFile = Native.CreateFile(fileName, FileAccess.Read, FileShare.Read, IntPtr.Zero, FileMode.Open, 0, IntPtr.Zero);

            if (hCertFile.IsInvalid)
            {
                throw new FileNotFoundException(string.Format("File not found: \"{0}\"", fileName), fileName);
            }
            dwFileSize = (int)(new FileInfo(fileName).Length); //GetFileSize(hCertFile, &dwFileSizeHi);
            pPFX = new Crypt.CRYPT_DATA_BLOB();
            pPFX.pbData = Crypt.CryptMemAlloc(dwFileSize * sizeof(byte));
            pPFX.cbData = dwFileSize;

            Native.ReadFile(hCertFile, pPFX.pbData, (uint)pPFX.cbData, out cbRead, IntPtr.Zero);
            hCertFile.Close();
        }

        static void GetPrivateKey(Crypt.CRYPT_DATA_BLOB pPFX, string szPassword, out IntPtr hCPContext, out IntPtr Info)
        {

            IntPtr hCertStore = IntPtr.Zero;
            IntPtr hCertContext;
            int dwKeySpec = Crypt.AT_SIGNATURE;
            int bFreeCertKey = 1; // aka TRUE
            int InfoSize = 0;

            hCPContext = IntPtr.Zero;

            try
            {
                hCertStore = Crypt.PFXImportCertStore(ref pPFX, szPassword, Crypt.CRYPT_EXPORTABLE);
                if (hCertStore == IntPtr.Zero)
                    throw new Win32Exception("PFXImportCertStore");
                hCertContext = Crypt.CertEnumCertificatesInStore(hCertStore, IntPtr.Zero);
                if (hCertContext == IntPtr.Zero)
                    throw new Win32Exception("CertEnumCertificatesInStore");
                if (Crypt.CryptAcquireCertificatePrivateKey(hCertContext, 0, IntPtr.Zero, ref hCPContext, ref dwKeySpec, ref bFreeCertKey) == 0)
                    throw new Win32Exception("CryptAcquireCertificatePrivateKey");
                if (Crypt.CertGetCertificateContextProperty(hCertContext, Crypt.CERT_KEY_PROV_INFO_PROP_ID, IntPtr.Zero, ref InfoSize) == 0)
                    throw new Win32Exception("CertGetCertificateContextProperty (Get Size)");
                Info = Crypt.CryptMemAlloc(sizeof(byte) * InfoSize);    // PCRYPT_KEY_PROV_INFO which is a pointer to a CRYPT_KEY_PROV_INFO in memory
                if (Crypt.CertGetCertificateContextProperty(hCertContext, Crypt.CERT_KEY_PROV_INFO_PROP_ID, Info, ref InfoSize) == 0)
                    throw new Win32Exception("CertGetCertificateContextProperty");
            }
            finally
            {
                if (hCertStore != IntPtr.Zero) Crypt.CertCloseStore(hCertStore, 0);
            }

        }

        static void PrintContainerName(IntPtr hCPContext)
        {

            uint containerNameLen = 0;
            IntPtr szContainerName = IntPtr.Zero;
            StringBuilder sb = null;

            try
            {

                if (!Crypt.CryptGetProvParam(hCPContext, Crypt.PP_CONTAINER, sb, ref containerNameLen, 0))
                    throw new Win32Exception("CryptGetProvParam (Get Size)");

                szContainerName = Crypt.CryptMemAlloc(sizeof(byte) * (int)containerNameLen);

                if (!Crypt.CryptGetProvParam(hCPContext, Crypt.PP_CONTAINER, szContainerName, ref containerNameLen, 0))
                    throw new Win32Exception("CryptGetProvParam");

                Console.WriteLine("Certificate's container name is: {0} [{1}]", Marshal.PtrToStringAnsi(szContainerName, (int)containerNameLen), containerNameLen);

            }
            finally
            {

                if (szContainerName != IntPtr.Zero) Crypt.CryptMemFree(szContainerName);

            }

        }

        static void MakeNewCert(IntPtr hCPContext, string szCertName, string szPassword, ref Crypt.CRYPT_DATA_BLOB pPFX, ref IntPtr Info)
        {

            Crypt.CRYPT_DATA_BLOB certNameBlob = new Crypt.CRYPT_DATA_BLOB();
            IntPtr hCertContext = IntPtr.Zero;
            Native.SYSTEMTIME certExpireDate;
            IntPtr hTempStore = IntPtr.Zero;

            try
            {

                if (!Crypt.CertStrToName(Crypt.X509Encoding.ASN_Encodings, szCertName, Crypt.CertNameType.CERT_OID_NAME_STR, IntPtr.Zero, null, ref certNameBlob.cbData, IntPtr.Zero))
                    throw new Win32Exception("CertStrToName");
                certNameBlob.pbData = Crypt.CryptMemAlloc(sizeof(byte) * certNameBlob.cbData);
                if (!Crypt.CertStrToName(Crypt.X509Encoding.ASN_Encodings, szCertName, Crypt.CertNameType.CERT_OID_NAME_STR, IntPtr.Zero, certNameBlob.pbData, ref  certNameBlob.cbData, IntPtr.Zero))
                    throw new Win32Exception("CertStrToName2");
                //var buffer = new char[1024];
                char[] buffer = new char[1024];

                int d;

                if ((d = Crypt.CertNameToStr(Crypt.X509Encoding.ASN_Encodings, ref certNameBlob, Crypt.CertNameType.CERT_X500_NAME_STR, buffer, 1024 * sizeof(char))) != 0)
                    Console.WriteLine("CertNameToStr: {0} [{1}]", buffer, d);

                var renewDate = DateTime.Now.AddYears(YearsToExtend);
                certExpireDate = new Native.SYSTEMTIME(renewDate);
                Console.WriteLine("  Renewing to expire at {0:g}", renewDate);

                // For some reason, evaluating this next line makes the create cert work
                var junk = string.Format("  {0}, {1}/{2}, {3}, {4}", hCPContext, certNameBlob.cbData, certNameBlob.pbData, Info, certExpireDate.ToDate());

                hCertContext = Crypt.CertCreateSelfSignCertificate(hCPContext, ref certNameBlob, 0, Info, IntPtr.Zero, null, certExpireDate, IntPtr.Zero);
                if (hCertContext == IntPtr.Zero)
                    throw new Win32Exception("CertCreateSelfSignCertificate");
                hTempStore = Crypt.CertOpenStore(new IntPtr(Crypt.CERT_STORE_PROV_MEMORY), 0, IntPtr.Zero, Crypt.CERT_STORE_CREATE_NEW_FLAG, null);
                if (hTempStore == IntPtr.Zero)
                    throw new Win32Exception("CertOpenStore");
                if (!Crypt.CertAddCertificateContextToStore(hTempStore, hCertContext, Crypt.CERT_STORE_ADD_NEW, IntPtr.Zero))
                    throw new Win32Exception("CertAddCertificateContextToStore");
                if (Crypt.PFXExportCertStoreEx(hTempStore, ref pPFX, szPassword, IntPtr.Zero, Crypt.ExportCertStoreFlags.EXPORT_PRIVATE_KEYS | Crypt.ExportCertStoreFlags.REPORT_NO_PRIVATE_KEY | Crypt.ExportCertStoreFlags.REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY) == 0)
                    throw new Win32Exception("PFXExportCertStoreEx");
                pPFX.pbData = Crypt.CryptMemAlloc(sizeof(byte) * pPFX.cbData);
                if (Crypt.PFXExportCertStoreEx(hTempStore, ref pPFX, szPassword, IntPtr.Zero, Crypt.ExportCertStoreFlags.EXPORT_PRIVATE_KEYS) == 0)
                    throw new Win32Exception("PFXExportCertStoreEx2");

            }
            finally
            {

                if (certNameBlob.pbData != IntPtr.Zero) Crypt.CryptMemFree(certNameBlob.pbData);
                if (hTempStore != IntPtr.Zero) Crypt.CertCloseStore(hTempStore, 0);
                if (hCertContext != IntPtr.Zero) Crypt.CertFreeCertificateContext(hCertContext);

            }

        }

        public static void WritePFX(Crypt.CRYPT_DATA_BLOB pPFX, string szOutputFile)
        {

            SafeFileHandle hOutputFile;
            int cbWritten = 0;

            hOutputFile = Native.CreateFile(szOutputFile, FileAccess.ReadWrite, 0, IntPtr.Zero, FileMode.Create, (FileAttributes)Native.FILE_FLAG_SEQUENTIAL_SCAN, IntPtr.Zero);
            if (hOutputFile.IsInvalid)
                throw new Win32Exception("CreateFile");

            if (!Native.WriteFile(hOutputFile, pPFX.pbData, (uint)pPFX.cbData, out cbWritten, IntPtr.Zero))
                throw new Win32Exception("WriteFile");

            hOutputFile.Close();

        }

        public static int Main(string[] args)
        {

            string szCertFileName = null;

            bool checkExpired = false;

            Crypt.CRYPT_DATA_BLOB pPFX = default(Crypt.CRYPT_DATA_BLOB);
            string szPassword = null;
            IntPtr hCPContext = IntPtr.Zero;

            string szCertName = null; // "CN=NewCert";
            Crypt.CRYPT_DATA_BLOB pPfxOutputBlob = default(Crypt.CRYPT_DATA_BLOB);
            string szOutFile = null;

            IntPtr provInfo;

            // Parse the command line.
            if (args.Length == 0)
            {
                goto ShowArgInfo;
            }

            if (args.Length >= 1) szCertFileName = args[0];
            if (args.Length >= 2)
            {
                if (args[1].ToUpper() == "/E")
                {
                    checkExpired = true;
                    if (args.Length >= 3) goto ShowArgInfo;
                }
                else
                {
                    szOutFile = args[1];
                    if (args.Length >= 3) szCertName = args[2];
                    if (args.Length >= 4) szPassword = args[3];
                    if (args.Length >= 5) goto ShowArgInfo;
                }
            }

            try
            {

                var c = new X509Certificate2(szCertFileName, szPassword);

                if (checkExpired)
                {
                    var expiration = DateTime.Parse(c.GetExpirationDateString());
                    Console.WriteLine("Expiration for '{0}' is {1:g}.", Path.GetFileName(szCertFileName), expiration);
                    if (Debugger.IsAttached) Console.ReadKey(true);
                    return (expiration < DateTime.Now) ? 1 : 0;
                }

                // Default to using same issuer
                szCertName = szCertName ?? c.Issuer;

            }
            catch (Exception ex)
            {
                Console.WriteLine("Couldn't open certificate: '{0}'", szCertFileName);
                Console.WriteLine(" Got error: {0}", ex.Message);
                if (Debugger.IsAttached) Console.ReadKey(true);
                return 1;
            }

            try
            {

                ReadPFXFile(szCertFileName, out pPFX);

                GetPrivateKey(pPFX, szPassword, out hCPContext, out provInfo);

                PrintContainerName(hCPContext); // For some reason this has to run for MakeNewCert to work successfully

                MakeNewCert(hCPContext, szCertName, szPassword, ref pPfxOutputBlob, ref provInfo);

                WritePFX(pPfxOutputBlob, szOutFile);

                var cnew = new X509Certificate2(szOutFile, szPassword);

                Console.WriteLine("Created File: {0}", szOutFile);
                if (Debugger.IsAttached) Console.ReadKey(true);

            }
            catch (Win32Exception ex)
            {

                Console.WriteLine("{0} failed with error {1}: {2}\nExiting...", ex.Message, ex.NativeErrorCode, Native.GetErrorMessage(ex.NativeErrorCode));
                if (Debugger.IsAttached) Console.ReadKey(true);

                return ex.NativeErrorCode;

            }
            catch (Exception ex)
            {

                Console.WriteLine("Unknown error: {0}\nExiting...", ex.Message);
                if (Debugger.IsAttached) Console.ReadKey(true);

                return 1;

            }
            finally
            {

                // Clean up
                if (hCPContext != IntPtr.Zero) Crypt.CryptReleaseContext(hCPContext, 0);
                if (pPfxOutputBlob.pbData != IntPtr.Zero) Crypt.CryptMemFree(pPfxOutputBlob.pbData);
                if (pPFX.pbData != IntPtr.Zero) Crypt.CryptMemFree(pPFX.pbData);

            }

            return 0;

        ShowArgInfo:

            Console.WriteLine("renewcert <PFX File> <new cert filename> <new cert friendly name> [optional]<password>");
            Console.WriteLine("  Renews certificate.");
            Console.WriteLine("  Example: renewcert oldcert.pfx newcert.pfx \"CN=MyNewCert\" MySuperSecretPassword");
            Console.WriteLine();
            Console.WriteLine("renewcert <PFX File> /e");
            Console.WriteLine("  Checks to see if cert is expired. Returns errorlevel 0 if not expired or 1 if expired.");
            Console.WriteLine("  Example: renewcert oldcert.pfx /e");
            Console.WriteLine();

            if (Debugger.IsAttached) Console.ReadKey(true);

            return 1;

        }

    }
}
