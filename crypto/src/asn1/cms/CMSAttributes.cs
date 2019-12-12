using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Asn1.Cms
{
    public abstract class CmsAttributes
    {
        public static readonly DerObjectIdentifier ContentType		= PkcsObjectIdentifiers.Pkcs9AtContentType;
        public static readonly DerObjectIdentifier MessageDigest	= PkcsObjectIdentifiers.Pkcs9AtMessageDigest;
        public static readonly DerObjectIdentifier SigningTime		= PkcsObjectIdentifiers.Pkcs9AtSigningTime;
		public static readonly DerObjectIdentifier CounterSignature = PkcsObjectIdentifiers.Pkcs9AtCounterSignature;
		public static readonly DerObjectIdentifier ContentHint		= PkcsObjectIdentifiers.IdAAContentHint;
        public static readonly DerObjectIdentifier SignDeviceType   = PkcsObjectIdentifiers.PkcsSigningDeviceType;
        public static readonly DerObjectIdentifier SignUnknown1     = PkcsObjectIdentifiers.PkcsSigningUnknown1;
        public static readonly DerObjectIdentifier SignUnknown2     = PkcsObjectIdentifiers.PkcsSigningUnknown2;
        public static readonly DerObjectIdentifier SignDeviceNumber = PkcsObjectIdentifiers.PkcsSigningDeviceNumber;
    }
}
