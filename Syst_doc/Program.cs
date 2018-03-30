using System;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using CERTENROLLLib;
using System.IO;



namespace Syst_doc
{
    class Program
    {
        const string defaultCertName = "testcert.crt";
        const string defaultSubjectName = "ALEXANDR";
        const string defaultSysInfoPath = "";
        const string defaultSysInfoName = "syst.tat";
        const string defaultPrivateKeyPath = "pk.xml";

        static int Main(string[] args)
        {

            // certificate
            X509Certificate2 mycert;

            // data
            string dataToSign;
            string certsubject;
            string certname;

            

            try
            {

                // Sign text

                //Signature is represented by array of bytes
                //To sign smth we need chunk of data and certificate with private key
                //The selfsigned cert may be used in this programm
                Console.WriteLine("The program provides simple interface to create certificates," +
                    "sign and verife files");
                Console.WriteLine();
                Console.WriteLine("Create a certificate or open?\n1 - create, 2 - open," +
                    " 3 - install syst.tat 0 - exit");
                string answer = Console.ReadLine();
                byte[] signature;
                if (answer == "1")
                {
                    Console.WriteLine("Enter certificate subject: (blank space for {0})", defaultSubjectName);
                    certsubject = Console.ReadLine();
                    certsubject = certsubject == "" ? defaultSubjectName : certsubject;

                    //create cert for subject
                    mycert = CreateSelfSignedCertificate(certsubject);
                    Console.WriteLine("Certificate was created sucessfully");
                    File.WriteAllText(defaultPrivateKeyPath, mycert.PrivateKey.ToXmlString(true));


                    //Export cert
                    string certexp = ExportToPEM(mycert);
                    Console.WriteLine("Enter certificate path to export: \n(blank space for current " +
                        "directory and name \"{0}\")", defaultCertName);
                    certname = Console.ReadLine();
                    certname = certname == "" ? defaultCertName : certname;
                    StreamWriter sw = new StreamWriter(certname);
                    sw.WriteLine(certexp);
                    sw.Close();
                    Console.WriteLine("Certificate {0} was exported sucessfully", certname);
                }
                else if (answer == "2")
                {
                    Console.WriteLine("Enter certificate path to open: \n(blank space for current " +
                        "directory and name \"{0}\")", defaultCertName);
                    certname = Console.ReadLine();
                    certname = certname == "" ? defaultCertName : certname;
                    mycert = new X509Certificate2(certname);
                }
                else if (answer == "3")
                {
                    //get directory
                    Console.WriteLine("Enter directory: (blank space for the same with programm)");
                    string systdocpath = Console.ReadLine();
                    if (!Directory.Exists(systdocpath) && (systdocpath != ""))
                        throw new Exception("Directory doesn't exist");

                    //grab info
                    string systeminfo = string.Format(
                        "User domain name: {0}{1}" +
                        "User name: {2}{3}" +
                        "Machine name: {4}{5}" +
                        "OS version: {6}",
                        Environment.UserDomainName, Environment.NewLine,
                        Environment.UserName, Environment.NewLine,
                        Environment.MachineName, Environment.NewLine,
                        Environment.OSVersion);

                    //write all info into the file
                    File.WriteAllText(systdocpath + defaultSysInfoName, systeminfo);
                    Console.WriteLine("System info was written to {0}", systdocpath + defaultSysInfoName);

                    Console.WriteLine("Enter certificate subject: (blank space for {0})", defaultSubjectName);
                    certsubject = Console.ReadLine();
                    certsubject = certsubject == "" ? defaultSubjectName : certsubject;

                    //create certificate
                    mycert = CreateSelfSignedCertificate(certsubject);
                    Console.WriteLine("Certificate was created sucessfully");

                    //Export cert
                    string certexp = ExportToPEM(mycert);
                    Console.WriteLine("Enter certificate path to export: \n(blank space for current " +
                        "directory and name \"{0}\")", defaultCertName);
                    certname = Console.ReadLine();
                    certname = certname == "" ? defaultCertName : certname;
                    StreamWriter sw = new StreamWriter(certname);
                    sw.WriteLine(certexp);
                    sw.Close();
                    Console.WriteLine("Certificate {0} was exported sucessfully", certname);

                    //take a look at our private key
                    File.WriteAllText(defaultPrivateKeyPath, mycert.PrivateKey.ToXmlString(true));
                    

                    //sign system info
                    dataToSign = systeminfo;
                    signature = Sign(dataToSign, mycert, "");
                    Console.WriteLine("System info was signed.");

                    //put signature into registry
                    //DO IT LATER:)

                    File.WriteAllBytes(systdocpath + defaultSysInfoName + ".sgtr", signature);
                    File.WriteAllText(systdocpath + defaultSysInfoName + ".sgtradv", ExportSignature(signature), Encoding.Unicode);
                    


                }

                else if (answer == "0")
                    return 0;
                else
                    throw new Exception("Invalid input");
                string filepath = "";
                
                while (true)
                {
                    Console.WriteLine("Choose file:");
                    filepath = Console.ReadLine();
                    if (!File.Exists(filepath)) throw new Exception("File does't exist");
                    dataToSign = File.ReadAllText(filepath);

                    Console.WriteLine("1 - sign data, 2 - verify data, 0 - exit");
                    answer = Console.ReadLine();

                    if (answer == "1")
                    {
                        string pk = File.ReadAllText(defaultPrivateKeyPath);
                        signature = Sign(dataToSign, mycert, pk);
                        Console.WriteLine("Signed successfully!!");
                        File.WriteAllBytes(filepath + ".sgtr", signature);
                        Console.WriteLine("Signature was written into \"{0}.sgtr\" file", filepath);
                    }

                    else if (answer == "2")
                    {
                        if (!File.Exists(filepath + ".sgtr")) 
                            Console.WriteLine("There is no signature for the {0}", filepath);
                        signature = File.ReadAllBytes(filepath + ".sgtr");
                        // Verify signature
                        if (Verify(dataToSign, signature, mycert))
                            Console.WriteLine("Signature verified");
                        else
                            Console.WriteLine("ERROR: Signature is not valid!");

                    }
                    else if (answer == "0")
                        break;
                    else
                        throw new Exception("Invalid input");

                }

            }
            catch (Exception ex)
            {
                Console.WriteLine("EXCEPTION: " + ex.Message);
            }

            Console.ReadKey();
            return 0;
        }



        static byte[] Sign(string text, X509Certificate2 cert, string pkxml)
        {

            //Create obj for private key 
            RSACryptoServiceProvider csp = null; 
            csp = (RSACryptoServiceProvider)cert.PrivateKey;
            
            //IF SONETHING GOES WRONG:)
            if (csp == null)
            //throw new Exception("No valid cert was found");
            {                
                CspParameters cspParams = new CspParameters();
                cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
                csp = new RSACryptoServiceProvider(cspParams);
                csp.PersistKeyInCsp = true;
                csp.FromXmlString(pkxml);
            }

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
            

            //To verify data we need only public key
            // Get its associated CSP and public key
            RSACryptoServiceProvider csp = (RSACryptoServiceProvider)cert.PublicKey.Key;
          
            // Hash the data
            SHA1Managed sha1 = new SHA1Managed();
            UnicodeEncoding encoding = new UnicodeEncoding();

            //Get data and hash as bytes array
            byte[] data = encoding.GetBytes(text);
            byte[] hash = sha1.ComputeHash(data);

            // Verify the signature with the hash
            return csp.VerifyHash(hash, CryptoConfig.MapNameToOID("SHA1"), signature);
        }

        public static X509Certificate2 CreateSelfSignedCertificate(string subjectName)
        {
            //To make a certificate was used system library from CERTENROLLLib
            //This lib provides methods for creation certificates in windows envinronment
            

            //Defines the subject and issuer of the cert
            CX500DistinguishedName dn = new CX500DistinguishedName();
            dn.Encode("CN=" + subjectName, X500NameFlags.XCN_CERT_NAME_STR_NONE);

            //Create a new private key for the certificate
            //Was decided not to make them variably in this progr
            CX509PrivateKey privateKey = new CX509PrivateKey();
            privateKey.ProviderName = "Microsoft Base Cryptographic Provider v1.0"; //issuer for a selfsigned certificate
            privateKey.MachineContext = true;
            privateKey.Length = 2048; 
            privateKey.KeySpec = X509KeySpec.XCN_AT_SIGNATURE; //Use is not limited
            privateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            privateKey.Create();

            //Use trong SHA512 hashing algorithm
            var hashobj = new CObjectId();
            hashobj.InitializeFromAlgorithmName(ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                AlgorithmFlags.AlgorithmFlagsNone, "SHA512");

            // Create the self signing request
            var cert = new CX509CertificateRequestCertificate();
            cert.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextMachine, privateKey, "");
            cert.Subject = dn;
            cert.Issuer = dn; // The issuer and the subject are the same
            cert.NotBefore = DateTime.Now;
            cert.NotAfter = new DateTime(2018, 12, 31); // I don't think that anybody cares about using this cert longer than this period
            cert.HashAlgorithm = hashobj; // Specify the hashing algorithm
            cert.Encode(); // Encode the certificate

            // Do the final stuff
            //Enroll is 
            var enroll = new CX509Enrollment();
            enroll.InitializeFromRequest(cert); // load the certificate
            string csr = enroll.CreateRequest(); // Output the request in base64
                                                 // and install it back as the response
            enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                csr, EncodingType.XCN_CRYPT_STRING_BASE64, ""); // no password
                                                                // output a base64 encoded PKCS#12 so we can import it back to the .Net security classes
            var base64encoded = enroll.CreatePFX("", // password isn't possible
                PFXExportOptions.PFXExportChainWithRoot);

            // instantiate the target class with the PKCS#12 data (and the empty password)
            return new X509Certificate2(Convert.FromBase64String(base64encoded), "",
                // mark the private key as exportable, coz we want to put it into registry 
                X509KeyStorageFlags.Exportable);
        }


        public static string ExportToPEM(X509Certificate cert)
        {

            //This methods return the exportable form of the cert
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), 
                Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

        public static string ExportSignature(byte[] sg)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine(Convert.ToBase64String(sg, Base64FormattingOptions.InsertLineBreaks));
            return builder.ToString();
        }

        

    }

}


