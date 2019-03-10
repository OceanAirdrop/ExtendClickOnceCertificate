using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

// http://searchco.de/codesearch/view/10672700
// http://searchco.de/codesearch/view/9854856#98
// http://searchco.de/codesearch/view/11297012#143

namespace NewRenewCert
{
    public static class Crypt
    {

        /// <summary>
        /// The CryptMemAlloc function allocates memory for a buffer. 
        /// It is used by all Crypt32.lib functions that return allocated buffers.
        /// </summary>
        /// <param name="cbSize">Number of bytes to be allocated. </param>
        /// <returns>Returns a pointer to the buffer allocated. 
        /// If the function fails, NULL is returned. </returns>
        //LPVOID WINAPI CryptMemAlloc(ULONG cbSize);
        [DllImport("crypt32.dll", EntryPoint = "CryptMemAlloc", SetLastError = true)]
        public static extern IntPtr CryptMemAlloc(int cbSize);

        /// <summary>
        /// The CryptMemFree function frees memory allocated by 
        /// CryptMemAlloc or CryptMemRealloc.
        /// </summary>
        /// <param name="pv">Pointer to the buffer to be freed. </param>
        //void WINAPI CryptMemFree(LPVOID pv);
        [DllImport("crypt32.dll", EntryPoint = "CryptMemFree", SetLastError = true)]
        public static extern void CryptMemFree(IntPtr pv);

        /// <summary>
        /// The CryptMemRealloc function frees the memory currently allocated for a buffer 
        /// and allocates memory for a new buffer.
        /// </summary>
        /// <param name="pv">Pointer to a currently allocated buffer. </param>
        /// <param name="cbSize">Number of bytes to be allocated. </param>
        /// <returns>Returns a pointer to the buffer allocated. 
        /// If the function fails, NULL is returned. </returns>
        //LPVOID WINAPI CryptMemRealloc(LPVOID pv, ULONG cbSize);
        [DllImport("crypt32.dll", EntryPoint = "CryptMemRealloc", SetLastError = true)]
        public static extern IntPtr CryptMemRealloc(IntPtr pv, int cbSize);

        public const uint CRYPT_EXPORTABLE = 0x00000001;

        /// <summary>
        /// PFXImportCertStore
        /// </summary>
        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr PFXImportCertStore(ref CRYPT_DATA_BLOB pPfx, [MarshalAs(UnmanagedType.LPWStr)] string szPassword, uint dwFlags);

        public enum ExportCertStoreFlags : uint
        {
            REPORT_NO_PRIVATE_KEY = 0x0001,
            REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY = 0x0002,
            EXPORT_PRIVATE_KEYS = 0x0004,
            PKCS12_EXPORT_RESERVED_MASK = 0xffff0000,
        }
        [DllImport(@"crypt32.dll", CharSet = CharSet.Unicode)]
        public static extern int PFXExportCertStoreEx(IntPtr hStore, ref CRYPT_DATA_BLOB pPFX, string szPassword, IntPtr pvReserved, ExportCertStoreFlags dwFlags);


        public const int CERT_STORE_PROV_MEMORY = 2;
        public const int CERT_STORE_CREATE_NEW_FLAG = 0x00002000;

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)] //overloaded
        public static extern IntPtr CertOpenStore(
            IntPtr storeProvider,
            uint dwMsgAndCertEncodingType,
            IntPtr hCryptProv,
            uint dwFlags,
            String cchNameString);

        public const int CERT_STORE_ADD_NEW = 1;

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertAddCertificateContextToStore(
            IntPtr hCertStore,
            IntPtr hCertificate,
            uint flags,
            IntPtr ppStoreContext); // technically should be "out"

        /// <summary>
        /// CertCloseStore
        /// </summary>
        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

        [Flags]
        public enum X509Encoding
        {
            CRYPT_ASN_ENCODING = 0x00000001,
            CRYPT_NDR_ENCODING = 0x00000002,
            X509_ASN_ENCODING = 0x00000001,
            X509_NDR_ENCODING = 0x00000002,
            PKCS_7_ASN_ENCODING = 0x00010000,
            PKCS_7_NDR_ENCODING = 0x00020000,
            ASN_Encodings = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
        }
        public enum CertNameType
        {
            CERT_SIMPLE_NAME_STR = 1,
            CERT_OID_NAME_STR = 2,
            CERT_X500_NAME_STR = 3,
        }
        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertStrToName(
            X509Encoding dwCertEncodingType,
            String pszX500,
            CertNameType dwStrType,
            IntPtr pvReserved,
            IntPtr pbEncoded,
            ref int pcbEncoded,
            IntPtr other);
        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertStrToName(
            X509Encoding dwCertEncodingType,
            String pszX500,
            CertNameType dwStrType,
            IntPtr pvReserved,
            [In, Out] byte[] pbEncoded,
            ref int pcbEncoded,
            IntPtr other);

        [DllImport("crypt32.dll", CharSet = CharSet.Auto)]
        internal static extern int CertNameToStr(X509Encoding dwCertEncodingType, ref CRYPT_DATA_BLOB pName, CertNameType dwStrType, [In, Out] char[] psz, int csz);

        /// <summary>
        /// CertEnumCertificatesInStore
        /// </summary>
        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CertEnumCertificatesInStore(IntPtr hCertStore, IntPtr pPrevCertContext);

        public const int AT_KEYEXCHANGE = 1;
        public const int AT_SIGNATURE = 2;

        [DllImport("crypt32.dll")]
        public static extern int CryptAcquireCertificatePrivateKey(IntPtr pCert, int dwFlags, IntPtr pvReserved, ref IntPtr phCryptProv, ref int pdwKeySpec, ref int pfCallerFreeProv);

        public const int CERT_KEY_PROV_INFO_PROP_ID = 2;

        [DllImport(@"crypt32.dll")]
        public static extern int CertGetCertificateContextProperty(IntPtr pCertContext, int dwPropId, IntPtr pvData, ref int pcbData);

        public const uint PP_NAME = 4;
        public const uint PP_CONTAINER = 6;

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptGetProvParam(
            IntPtr hProv,
            uint dwParam,
            IntPtr pbData,
            ref uint dwDataLen,
            uint dwFlags);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptGetProvParam(
            IntPtr hProv,
            uint dwParam,
            [In, Out] byte[] pbData,
            ref uint dwDataLen,
            uint dwFlags);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptGetProvParam(
            IntPtr hProv,
            uint dwParam,
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder pbData,
            ref uint dwDataLen,
            uint dwFlags);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CertCreateSelfSignCertificate(
            IntPtr hProv,
            ref CRYPT_DATA_BLOB pSubjectIssuerBlob,
            uint dwFlagsm,
            IntPtr pinfo,
            IntPtr pSignatureAlgorithm,
            Native.SYSTEMTIME pStartTime,
            Native.SYSTEMTIME pEndTime,
            IntPtr other);


        [DllImport(@"crypt32.dll")]
        public static extern int CertFreeCertificateContext(IntPtr pCertContext);

        [DllImport("advapi32.dll")]
        public static extern bool CryptReleaseContext(IntPtr hProv, uint dwFlags);

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CRYPT_KEY_PROV_INFO
        {
            internal string pwszContainerName;
            internal string pwszProvName;
            internal uint dwProvType;
            internal uint dwFlags;
            internal uint cProvParam;
            internal IntPtr rgProvParam;
            internal uint dwKeySpec;
        }
    }
}
