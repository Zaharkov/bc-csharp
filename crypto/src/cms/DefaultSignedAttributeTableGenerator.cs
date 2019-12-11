using System;
using System.Collections;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using AttributeTable = Org.BouncyCastle.Asn1.Cms.AttributeTable;
using Time = Org.BouncyCastle.Asn1.Cms.Time;

namespace Org.BouncyCastle.Cms
{
	/**
	 * Default signed attributes generator.
	 */
	public class DefaultSignedAttributeTableGenerator
		: CmsAttributeTableGenerator
	{
		private readonly IDictionary table;

		/**
		 * Initialise to use all defaults
		 */
		public DefaultSignedAttributeTableGenerator()
		{
			table = Platform.CreateHashtable();
		}

		/**
		 * Initialise with some extra attributes or overrides.
		 *
		 * @param attributeTable initial attribute table to use.
		 */
		public DefaultSignedAttributeTableGenerator(
			AttributeTable attributeTable)
		{
			if (attributeTable != null)
			{
				table = attributeTable.ToDictionary();
			}
			else
			{
				table = Platform.CreateHashtable();
			}
		}

#if SILVERLIGHT || PORTABLE
		/**
		 * Create a standard attribute table from the passed in parameters - this will
		 * normally include contentType, signingTime, and messageDigest. If the constructor
		 * using an AttributeTable was used, entries in it for contentType, signingTime, and
		 * messageDigest will override the generated ones.
		 *
		 * @param parameters source parameters for table generation.
		 *
		 * @return a filled in Hashtable of attributes.
		 */
		protected virtual IDictionary createStandardAttributeTable(
			IDictionary parameters)
		{
            IDictionary std = Platform.CreateHashtable(table);
            DoCreateStandardAttributeTable(parameters, std);
            return std;
		}
#else
        /**
		 * Create a standard attribute table from the passed in parameters - this will
		 * normally include contentType, signingTime, and messageDigest. If the constructor
		 * using an AttributeTable was used, entries in it for contentType, signingTime, and
		 * messageDigest will override the generated ones.
		 *
		 * @param parameters source parameters for table generation.
		 *
		 * @return a filled in Hashtable of attributes.
		 */
		protected virtual Hashtable createStandardAttributeTable(
			IDictionary parameters)
		{
            Hashtable std = new Hashtable(table);
            DoCreateStandardAttributeTable(parameters, std);
			return std;
		}
#endif

        private void DoCreateStandardAttributeTable(IDictionary parameters, IDictionary std)
        {
            // contentType will be absent if we're trying to generate a counter signature.
            if (parameters.Contains(CmsAttributeTableParameter.ContentType))
            {
                if (!std.Contains(CmsAttributes.ContentType))
                {
                    DerObjectIdentifier contentType = (DerObjectIdentifier)
                        parameters[CmsAttributeTableParameter.ContentType];
                    Asn1.Cms.Attribute attr = new Asn1.Cms.Attribute(CmsAttributes.ContentType,
                        new DerSet(contentType));
                    std[attr.AttrType] = attr;
                }
            }

            if (parameters.Contains(CmsAttributeTableParameter.DigestAlgorithmIdentifier))
            {
                var digestAlgorithm = (AlgorithmIdentifier) 
                    parameters[CmsAttributeTableParameter.DigestAlgorithmIdentifier];

                if ((digestAlgorithm.Algorithm.Id == RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.Id || 
                     digestAlgorithm.Algorithm.Id == RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.Id) &&
                    !std.Contains(CmsAttributes.SignDeviceType))
                {
                    Asn1.Cms.Attribute attr = new Asn1.Cms.Attribute(CmsAttributes.SignDeviceType,
                        new DerSet(PkcsObjectIdentifiers.PkcsSigningDeviceTypeSimple));
                    std[attr.AttrType] = attr;
                }
            }

            if (!std.Contains(CmsAttributes.SigningTime))
            {
                Asn1.Cms.Attribute attr = new Asn1.Cms.Attribute(CmsAttributes.SigningTime,
                    new DerSet(new Time(DateTime.UtcNow)));
                std[attr.AttrType] = attr;
            }

            if (!std.Contains(CmsAttributes.MessageDigest))
            {
                byte[] messageDigest = (byte[])parameters[CmsAttributeTableParameter.Digest];
                Asn1.Cms.Attribute attr = new Asn1.Cms.Attribute(CmsAttributes.MessageDigest,
                    new DerSet(new DerOctetString(messageDigest)));
                std[attr.AttrType] = attr;
            }
        }

        /**
		 * @param parameters source parameters
		 * @return the populated attribute table
		 */
		public virtual AttributeTable GetAttributes(
			IDictionary parameters)
		{
            IDictionary table = createStandardAttributeTable(parameters);
			return new AttributeTable(table);
		}
	}
}
