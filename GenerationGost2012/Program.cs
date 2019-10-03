using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using X509Extension = Org.BouncyCastle.Asn1.X509.X509Extension;

namespace GenerationGost2012
{
    class Program
    {
        private const string SingingAlgorithm = "GOST3411_2012_256WITHECGOST3410";
        private const string SignatureAlgorithm = "GOST3411_2012_256WITHECGOST3410";
        private const string KeyAlgorithm = "ECGOST3411-2012-256";
        // in my case need [B] parameter GostR3410x2001CryptoPro[B]
        private static readonly DerObjectIdentifier PublicKeyParamSet = CryptoProObjectIdentifiers.GostR3410x2001CryptoProB;
        private const int CertificateNumber = 1;
        private const string Password = "password";

        public static void Main()
        {
            GenerateBouncyCastleCertificate();
            
            var data = new Dictionary<string, string>
            {
                {"param1", "Mery" },
                {"param2", "have"},
                {"param3", "nuclear bomb" }
            };

            var digest = string.Join("\n", data.Select(t => $"{t.Key}={t.Value}"));
            // for GOST 2012 need full CMS
            var signCms = Cms(digest); //
            /* add signature to request */
        }

        #region Generate

        private static AsymmetricCipherKeyPair GetKeyPair()
        {
            // this is wont working for ECGost3410Parameters
            //var generator = GeneratorUtilities.GetKeyPairGenerator(KeyAlgorithm);
            //generator.Init(new ECKeyGenerationParameters(PublicKeyParamSet, new SecureRandom()));
            //return generator.GenerateKeyPair();

            // we need generate "specific" key for GOST 2012 BUT with paramSet from GOST 2001 (B) 
            var ecp = new ECNamedDomainParameters(PublicKeyParamSet, ECGost3410NamedCurves.GetByOid(PublicKeyParamSet));
            var gostParams = new ECGost3410Parameters(ecp, PublicKeyParamSet, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, null);
            var parameters = new ECKeyGenerationParameters(gostParams, new SecureRandom());
            var generator = new ECKeyPairGenerator();
            generator.Init(parameters);
            return generator.GenerateKeyPair();
        }

        private static X509Name GetSubjectData()
        {
            IDictionary attrs = new Hashtable
            {
                { X509Name.C, "RU" },
                { X509Name.O, "ООО \"ПАРТНЕР-XXX\"" },
                { X509Name.L, "Moscow" },
                { X509Name.ST, "Moscow" },
                { X509Name.Street, "TEST" },
                { X509Name.OU, "TEST" },
                { X509Name.CN, "ФамXXX ИмяXXX ОтчXXX" },
                { X509Name.Surname, "ФамXXX" },
                { X509Name.GivenName, "ИмяXXX ОтчXXX" },
                { X509Name.EmailAddress, "test@test.test" },
                { X509Name.T, "developer" }
            };
            var inn = new DerObjectIdentifier("1.2.643.3.131.1.1");
            attrs.Add(inn, "007705964240");
            var snils = new DerObjectIdentifier("1.2.643.100.3");
            attrs.Add(snils, "37709768946");
            attrs.Add(X509Name.SerialNumber, CertificateNumber.ToString());

            var order = new ArrayList
            {
                X509Name.C,
                X509Name.O,
                X509Name.L,
                X509Name.ST,
                X509Name.Street,
                X509Name.OU,
                X509Name.CN,
                X509Name.Surname,
                X509Name.GivenName,
                X509Name.EmailAddress,
                X509Name.T,
                inn,
                snils,
                X509Name.SerialNumber
            };

            return new X509Name(order, attrs);
        }

        private static List<CertificateExtension> GetExtensions(AsymmetricKeyParameter publicKey)
        {
            var extensions = new List<CertificateExtension>();

            var bicryptIdentifier = new DerObjectIdentifier("1.2.643.3.123.3.1");
            var parentAs = new DerObjectIdentifier("1.2.643.3.123.3.4");

            extensions.Add(new CertificateExtension(X509Extensions.KeyUsage, true, new DerBitString(0xF8)));
            extensions.Add(new CertificateExtension(bicryptIdentifier, false, new DerUtf8String($"A003EC0{CertificateNumber}sФам24002")));
            extensions.Add(new CertificateExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false)));
            extensions.Add(new CertificateExtension(parentAs, false, new DerObjectIdentifier("1.2.643.3.123.5.4")));
            extensions.Add(new CertificateExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(publicKey)));

            return extensions;
        }

        private class CertificateExtension
        {
            public CertificateExtension(DerObjectIdentifier id, bool critical, Asn1Encodable value)
            {
                Id = id;
                Critical = critical;
                Value = value;
            }
            public DerObjectIdentifier Id { get; }
            public bool Critical { get; }
            public Asn1Encodable Value { get; }
        }

        private static void GenerateBouncyCastleCertificate()
        {
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), new SecureRandom());
            var date = DateTime.UtcNow.Date;
            var keyPair = GetKeyPair();
            var subject = GetSubjectData();
            var attributes = GetExtensions(keyPair.Public);

            var certificateGenerator = new X509V3CertificateGenerator();
            
            certificateGenerator.SetSerialNumber(serialNumber);
            certificateGenerator.SetSubjectDN(subject);
            certificateGenerator.SetIssuerDN(new X509Name("CN=XXX"));
            certificateGenerator.SetNotBefore(date);
            certificateGenerator.SetNotAfter(date.AddYears(2));
            certificateGenerator.SetPublicKey(keyPair.Public);
            
            foreach (var attribute in attributes)
                certificateGenerator.AddExtension(attribute.Id, attribute.Critical, attribute.Value);
            
            var factory = new Asn1SignatureFactory(SignatureAlgorithm, keyPair.Private);
            
            var bcCertificate = certificateGenerator.Generate(factory);
            
            SavePrivateKey((ECPrivateKeyParameters)keyPair.Private);
            SaveCertificate(bcCertificate);

            IList oids = new ArrayList();
            IList values = new ArrayList();

            foreach (var attribute in attributes)
            {
                oids.Add(attribute.Id);
                values.Add(new X509Extension(attribute.Critical, new DerOctetString(attribute.Value.GetDerEncoded())));
            }

            var extensions = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(new X509Extensions(oids, values)));
            var request = new Pkcs10CertificationRequest(SignatureAlgorithm, subject, keyPair.Public, new DerSet(extensions), keyPair.Private);

            /* Есть 2 стула... */

            /* Первый - можно просто оформить чистый запрос на сертификат PKCS#10
             * В нем не будет никаких других подписей, он максимально простой
             * и по сути в нем есть все необходимое чтобы потом подписывать документы, если банк его "примет"
             */
            SavePkcs10Data(request);

            /* Второй - если в обязательном порядке нужен "заверенный" сертификат PKCS#7
             * Для этого его нужно подписать другим сертификатом выданным от "сертифицированного СКЗИ"
             * Соответственно нужен сам сертификат (преобразованный в Bouncy Castle) + приватный ключ для подписи
             * С первым понятно откуда брать, а вот как вы "вытащите" приватный ключ... я не смог =)
             * Но код на всякий случай оставил тут
             * SavePkcs7Data(certificateForSign, request, PrivateKeyForSign);
             */
        }

        #endregion

        #region Save

        private static void SaveCertificate(X509Certificate bcCertificate)
        {
            var certificate = new X509Certificate2(bcCertificate.GetEncoded(), Password);
            var certificateData = certificate.Export(X509ContentType.Pkcs12, Password);
            File.WriteAllBytes(@"certificate.pfx", certificateData); //save certificate
        }

        private static void SavePkcs10Data(Pkcs10CertificationRequest request)
        {
            var requestBytes = request.GetEncoded();
            var cmsBase64 = Convert.ToBase64String(requestBytes);

            /*
             * you can check cert data here - https://lapo.it/asn1js
             * just copy+paste cmsBase64 string
             */

            var cmsData = new StringBuilder();
            cmsData.Append("-----BEGIN CERTIFICATE REQUEST-----");
            cmsData.Append("\\n");

            var certLength = cmsBase64.Length;
            for (var i = 0; i < certLength; i += 64)
            {
                var substr = certLength - i >= 64
                    ? cmsBase64.Substring(i, 64)
                    : cmsBase64.Substring(i);

                cmsData.Append(substr);
                cmsData.Append("\\n");
            }

            cmsData.Append("-----END CERTIFICATE REQUEST-----");
            cmsData.Append("\\n");
            var cmsString = cmsData.ToString();  //add to http request in bank for approving you certificate
            //after you will need copy bank certificate what approved you certificate from API

            File.WriteAllText(@"certificate.cms", cmsString);
        }

        private static void SavePkcs7Data(X509Certificate bcCertificate, Pkcs10CertificationRequest request, AsymmetricKeyParameter privateKey)
        {
            var requestBytes = request.GetEncoded();

            var typedData = new CmsProcessableByteArray(requestBytes);
            var gen = new CmsSignedDataGenerator();
            var signerInfoGeneratorBuilder = new SignerInfoGeneratorBuilder();

            var factory = new Asn1SignatureFactory(SingingAlgorithm, privateKey);

            gen.AddSignerInfoGenerator(signerInfoGeneratorBuilder.Build(factory, bcCertificate));
            gen.AddCertificates(MakeCertStore(bcCertificate));

            var signed = gen.Generate(typedData, true);
            var signedBytes = signed.GetEncoded();
            var cmsBase64 = Convert.ToBase64String(signedBytes);

            /*
             * you can check cert data here - https://lapo.it/asn1js
             * just copy+paste cmsBase64 string
             */

            var cmsData = new StringBuilder();
            cmsData.Append("-----BEGIN CMS-----");
            cmsData.Append("\\n");

            var certLength = cmsBase64.Length;
            for (var i = 0; i < certLength; i += 64)
            {
                var substr = certLength - i >= 64
                    ? cmsBase64.Substring(i, 64)
                    : cmsBase64.Substring(i);

                cmsData.Append(substr);
                cmsData.Append("\\n");
            }

            cmsData.Append("-----END CMS-----");
            cmsData.Append("\\n");
            var cmsString = cmsData.ToString();  //add to http request in bank for approving you certificate
            //after you will need copy bank certificate what approved you certificate from API

            File.WriteAllText(@"certificate.cms", cmsString);
        }

        private static IX509Store MakeCertStore(params X509Certificate[] certs)
        {
            IList certList = new ArrayList();
            foreach (X509Certificate cert in certs)
            {
                certList.Add(cert);
            }

            return X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(certList));
        }

        private static void SavePrivateKey(ECPrivateKeyParameters privateKey)
        {
            var bytes = privateKey.D.ToByteArray();
            File.WriteAllBytes(@"private.key", bytes); //save private key (will need to sign)
        }

        #endregion

        #region Sing

        private static string Cms(string data)
        {
            var requestBytes = Encoding.UTF8.GetBytes(data);
            var typedData = new CmsProcessableByteArray(requestBytes);
            var gen = new CmsSignedDataGenerator();
            var signerInfoGeneratorBuilder = new SignerInfoGeneratorBuilder();

            var factory = new Asn1SignatureFactory(SingingAlgorithm, GetKey());

            var bcCertificate = GetBankCertificate();
            gen.AddSignerInfoGenerator(signerInfoGeneratorBuilder.Build(factory, bcCertificate));
            gen.AddCertificates(MakeCertStore(bcCertificate));

            var signed = gen.Generate(typedData, false);
            var signedBytes = signed.GetEncoded();

            return  Convert.ToBase64String(signedBytes);
        }

        private static ECPrivateKeyParameters GetKey()
        {
            var bytes = File.ReadAllBytes(@"private.key");
            var key = new BigInteger(bytes);
            return new ECPrivateKeyParameters(KeyAlgorithm, key, PublicKeyParamSet);
        }

        private static X509Certificate GetBankCertificate()
        {
            //base64 encoded bank (!) certificate
            //you can get it, when bank will "approve" your CMS request from API
            //so just copy paste bank certificate from API
            /*
             * "uuid": "....",
             * "active": true,
             * "cert": "-----BEGIN CERTIFICATE-----\r\nMIIEk....
             * remove all \r\n and comments and paste in bankCertificate.txt
             */
            var sbercert = File.ReadAllText("bankCertificate.txt"); 
            var sberBytes = Convert.FromBase64String(sbercert);
            var parser = new X509CertificateParser();
            return parser.ReadCertificate(sberBytes);
        }

        #endregion
    }
}
