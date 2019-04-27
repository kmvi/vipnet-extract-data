using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace VipNetExtract
{
    interface IExport
    {
        void Export(VipNetContainer container, string pin, Stream output);
    }

    class PrivateKeyExport : IExport
    {
        public void Export(VipNetContainer container, string pin, Stream output)
        {
            var privateKey = EncodePrivateKey(container, pin);
            var pemObject = new PemObject("PRIVATE KEY", privateKey.GetDerEncoded());
            using (var sw = new StreamWriter(output)) {
                var writer = new PemWriter(sw);
                writer.WriteObject(pemObject);
            }
        }

        private static Asn1Object EncodePrivateKey(VipNetContainer container, string pin)
        {
            var entry = container.Entries[0];
            var gostParams = Gost3410PublicKeyAlgParameters.GetInstance(entry.KeyInfo.Algorithm.Parameters);

            return new DerSequence(
                new DerInteger(0),
                new DerSequence(
                    entry.KeyInfo.Algorithm.Algorithm,
                    new DerSequence(
                        gostParams.PublicKeyParamSet,
                        gostParams.DigestParamSet
                    )
                ),
                new DerOctetString(new DerInteger(entry.GetPrivateKey(pin)))
            );
        }
    }

    class CertificateExport : IExport
    {
        public void Export(VipNetContainer container, string pin, Stream output)
        {
            var cert = container.Entries[0].Certificate;
            if (cert == null)
                throw new InvalidOperationException("Контейнер не содержит сертификата");

            var pemObject = new PemObject("CERTIFICATE", cert.GetEncoded());
            using (var sw = new StreamWriter(output)) {
                var writer = new PemWriter(sw);
                writer.WriteObject(pemObject);
            }
        }
    }
}
