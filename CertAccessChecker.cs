using System;
using System.Security.Cryptography.X509Certificates;


namespace CertAccessChecker
{
    class Program
    {
        static void Main(string[] args)
        {
            var hostingCertificates = GetCertificates("WebHosting");
            var myCertificates = GetCertificates("My");
            var certificates = new X509Certificate2Collection();
            certificates.AddRange(hostingCertificates);
            certificates.AddRange(myCertificates);
            Console.WriteLine("Scan complete, added {0} certificates as valid.", certificates.Count);
        }

        static X509Certificate2Collection GetCertificates(string storeName)
        {
            var store = new X509Store(storeName, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            var results = new X509Certificate2Collection();
            foreach (var cert in store.Certificates)
            {
                Console.WriteLine("Found Certificate: {0}", cert.Subject);
                if (cert.HasPrivateKey)
                {
                    Console.WriteLine("Has .HasPrivateKey set, adding as a valid option.");
                    results.Add(cert);
                }
            }

            store.Close();
            return results;
        }
    }
}
