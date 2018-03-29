using System;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using CERTENROLLLib;
using System.IO;



namespace ConsoleApplication1
{
    class Program
    {
        //test things
        const string certsubject = "ALEXANDR";
        const string certname = "testcert.cert";

        static void Main(string[] args)
        {
            
            //Create certificate
            X509Certificate2 mycert = CreateSelfSignedCertificate(certsubject);

            try
            {
                //test data
                string dataToSign = "Test";

                // Sign text

                //Signature is represented by array of bytes
                //To sign smth we need chunk of data and certificate with private key
                //The selfsigned cert may be used in this programm
                byte[] signature = Sign(dataToSign, mycert);
                Console.WriteLine("Signed successfully!!");

                //Ecport cert
                string certexp = ExportToPEM(mycert);
                StreamWriter sw = new StreamWriter(certname);
                sw.WriteLine(certexp);
                sw.Close();


                // Verify signature
                if (Verify(dataToSign, signature, certname))
                    Console.WriteLine("Signature verified");
                else
                    Console.WriteLine("ERROR: Signature not valid!");

            }
            catch (Exception ex)
            {
                Console.WriteLine("EXCEPTION: " + ex.Message);
            }

            Console.ReadKey();

        }



        static byte[] Sign(string text, X509Certificate2 cert)
        {

            //Create obj for private key 
            RSACryptoServiceProvider csp = null; 
            csp = (RSACryptoServiceProvider)cert.PrivateKey;
            
            //IF SONETHING GOES WRONG:)
            if (csp == null)
                throw new Exception("No valid cert was found");

            // Hash the data
            //There are cool methods in .NET dor cryptography and hashes
            SHA1Managed sha1 = new SHA1Managed();
            UnicodeEncoding encoding = new UnicodeEncoding();

            //to encode we may use bytes array
            byte[] data = encoding.GetBytes(text);
            byte[] hash = sha1.ComputeHash(data);


            // Sign the hash
            return csp.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));

        }


        static bool Verify(string text, byte[] signature, X509Certificate2 cert)
        {

            
            // Load the certificate we'll use to verify the signature from a file
            //Not needed actually
            //X509Certificate2 cert = new X509Certificate2(certPath);

            // Note:

            // If we want to use the client cert in an ASP.NET app, we may use something like this instead:

            // X509Certificate2 cert = new X509Certificate2(Request.ClientCertificate.Certificate);


            // Get its associated CSP and public key

            RSACryptoServiceProvider csp = (RSACryptoServiceProvider)cert.PublicKey.Key;


            // Hash the data

            SHA1Managed sha1 = new SHA1Managed();

            UnicodeEncoding encoding = new UnicodeEncoding();

            byte[] data = encoding.GetBytes(text);

            byte[] hash = sha1.ComputeHash(data);


            // Verify the signature with the hash

            return csp.VerifyHash(hash, CryptoConfig.MapNameToOID("SHA1"), signature);

        }

        public static X509Certificate2 CreateSelfSignedCertificate(string subjectName)
        {
            // create DN for subject and issuer
            var dn = new CX500DistinguishedName();
            dn.Encode("CN=" + subjectName, X500NameFlags.XCN_CERT_NAME_STR_NONE);

            // create a new private key for the certificate
            CX509PrivateKey privateKey = new CX509PrivateKey();
            privateKey.ProviderName = "Microsoft Base Cryptographic Provider v1.0";
            privateKey.MachineContext = true;
            privateKey.Length = 2048;
            privateKey.KeySpec = X509KeySpec.XCN_AT_SIGNATURE; // use is not limited
            privateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            privateKey.Create();

            // Use the stronger SHA512 hashing algorithm
            var hashobj = new CObjectId();
            hashobj.InitializeFromAlgorithmName(ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                AlgorithmFlags.AlgorithmFlagsNone, "SHA512");

            // add extended key usage if you want - look at MSDN for a list of possible OIDs
            var oid = new CObjectId();
            oid.InitializeFromValue("1.3.6.1.5.5.7.3.1"); // SSL server
            var oidlist = new CObjectIds();
            oidlist.Add(oid);
            var eku = new CX509ExtensionEnhancedKeyUsage();
            eku.InitializeEncode(oidlist);

            // Create the self signing request
            var cert = new CX509CertificateRequestCertificate();
            cert.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextMachine, privateKey, "");
            cert.Subject = dn;
            cert.Issuer = dn; // the issuer and the subject are the same
            cert.NotBefore = DateTime.Now;
            // this cert expires immediately. Change to whatever makes sense for you
            cert.NotAfter = new DateTime(2018, 12, 31);
            cert.X509Extensions.Add((CX509Extension)eku); // add the EKU
            cert.HashAlgorithm = hashobj; // Specify the hashing algorithm
            cert.Encode(); // encode the certificate

            // Do the final enrollment process
            var enroll = new CX509Enrollment();
            enroll.InitializeFromRequest(cert); // load the certificate
            enroll.CertificateFriendlyName = subjectName; // Optional: add a friendly name
            string csr = enroll.CreateRequest(); // Output the request in base64
                                                 // and install it back as the response
            enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                csr, EncodingType.XCN_CRYPT_STRING_BASE64, ""); // no password
                                                                // output a base64 encoded PKCS#12 so we can import it back to the .Net security classes
            var base64encoded = enroll.CreatePFX("", // no password, this is for internal consumption
                PFXExportOptions.PFXExportChainWithRoot);

            // instantiate the target class with the PKCS#12 data (and the empty password)
            return new X509Certificate2(Convert.FromBase64String(base64encoded), "",
                // mark the private key as exportable (this is usually what you want to do)
                X509KeyStorageFlags.Exportable);
        }


        public static string ExportToPEM(X509Certificate cert)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), 
                Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

    }

}


