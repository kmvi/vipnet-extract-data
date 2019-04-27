using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace VipNetExtract
{
    class KeyValidity : Asn1Encodable
    {
        public KeyValidity(Asn1Sequence seq)
        {
            NotBefore = Time.GetInstance(GetTime(seq[0]));
            NotAfter = Time.GetInstance(GetTime(seq[1]));
        }

        private static Asn1Encodable GetTime(Asn1Encodable time)
        {
            if (time is Asn1TaggedObject tag)
                time = tag.GetObject();

            if (time is Asn1OctetString str)
                time = new DerGeneralizedTime(Strings.FromAsciiByteArray(str.GetOctets()));

            return time;
        }

        public Time NotBefore { get; }
        public Time NotAfter { get; }

        public override Asn1Object ToAsn1Object()
        {
            throw new NotImplementedException();
        }

        public static KeyValidity GetInstance(object obj)
        {
            if (obj is KeyValidity entry)
                return entry;

            return new KeyValidity(Asn1Sequence.GetInstance(obj));
        }

        public static KeyValidity GetInstance(Asn1TaggedObject obj, bool explicitly)
            => GetInstance(Asn1Sequence.GetInstance(obj, explicitly));
    }
}
