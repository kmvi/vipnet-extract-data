using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;

namespace VipNetExtract
{
    class VipNetKeyInfo : Asn1Encodable
    {
        public VipNetKeyInfo(Asn1Sequence seq)
        {
            RawData = seq.GetEncoded();
            KeyClass = (DerInteger)seq[0];
            KeyType = (DerInteger)seq[1];

            for (int i = 2; i < seq.Count; ++i) {
                if (seq[i] is Asn1TaggedObject tag) {
                    switch (tag.TagNo) {
                        case 0:
                            Algorithm = AlgorithmIdentifier.GetInstance(tag.GetObject());
                            break;
                        case 1:
                            SerialNumber = Asn1OctetString.GetInstance(tag.GetObject());
                            break;
                        case 2:
                            AddSerialNumber = Asn1OctetString.GetInstance(tag.GetObject());
                            break;
                        case 3:
                            CertSerialNumber = Asn1OctetString.GetInstance(tag.GetObject());
                            break;
                        case 4:
                            SubjectUID = Asn1OctetString.GetInstance(tag.GetObject());
                            break;
                        case 5:
                            RecipientUID = Asn1OctetString.GetInstance(tag.GetObject());
                            break;
                        case 6:
                            Validity = KeyValidity.GetInstance(tag.GetObject());
                            break;
                        case 7:
                            KeyUID = DerBitString.GetInstance(tag.GetObject());
                            break;
                        case 10:
                            Flags = DerInteger.GetInstance(tag.GetObject());
                            break;
                    }
                }
            }
        }

        internal byte[] RawData { get; }

        public DerInteger KeyClass { get; }
        public DerInteger KeyType { get; }
        public AlgorithmIdentifier Algorithm { get; }
        public Asn1OctetString SerialNumber { get; }
        public Asn1OctetString AddSerialNumber { get; }
        public Asn1OctetString CertSerialNumber { get; }
        public Asn1OctetString SubjectUID { get; }
        public Asn1OctetString RecipientUID { get; }
        public KeyValidity Validity { get; }
        public DerBitString KeyUID { get; }
        public DerInteger Flags { get; }

        public override Asn1Object ToAsn1Object()
        {
            var vec = new Asn1EncodableVector(KeyClass, KeyType);

            if (Algorithm != null)
                vec.Add(new DerTaggedObject(0, Algorithm));

            if (SerialNumber != null)
                vec.Add(new DerTaggedObject(1, SerialNumber));

            if (AddSerialNumber != null)
                vec.Add(new DerTaggedObject(2, AddSerialNumber));

            if (CertSerialNumber != null)
                vec.Add(new DerTaggedObject(3, CertSerialNumber));

            if (SubjectUID != null)
                vec.Add(new DerTaggedObject(4, SubjectUID));

            if (RecipientUID != null)
                vec.Add(new DerTaggedObject(5, RecipientUID));

            if (Validity != null)
                vec.Add(new DerTaggedObject(6, Validity));

            if (KeyUID != null)
                vec.Add(new DerTaggedObject(7, KeyUID));

            if (Flags != null)
                vec.Add(new DerTaggedObject(10, Flags));

            return new DerSequence(vec);
        }

        public static VipNetKeyInfo GetInstance(object obj)
        {
            if (obj is VipNetKeyInfo keyInfo)
                return keyInfo;

            return new VipNetKeyInfo(Asn1Sequence.GetInstance(obj));
        }

        public static VipNetKeyInfo GetInstance(Asn1TaggedObject obj, bool explicitly)
            => GetInstance(Asn1Sequence.GetInstance(obj, explicitly));
    }
}
