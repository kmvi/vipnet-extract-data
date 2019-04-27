using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Mono.Options;
using Org.BouncyCastle.Utilities.Encoders;

namespace VipNetExtract
{
    class Program
    {
        enum Mode
        {
            Private, Certificate
        }

        private static OptionSet options;

        static void Main(string[] args)
        {
            string file = null, pin = null;
            Mode mode = Mode.Private;
            bool showHelp = false;

            options = new OptionSet {
                { "f|file=",  "Путь к контейнеру", f => file = f },
                { "private", "Извлечь закрытый ключ (по умолчанию)", p => { if (p != null) mode = Mode.Private; } },
                { "cert", "Извлечь сертификат", c => { if (c != null) mode = Mode.Certificate; } },
                { "p|pin=", "ПИН-код", p => pin = p },
                { "h|help", "Помощь", h => showHelp = h != null}
            };

            try {
                options.Parse(args);
            } catch (OptionException e) {
                Console.Error.WriteLine(e.Message);
                return;
            }

            if (showHelp || String.IsNullOrEmpty(file)) {
                PrintHelp();
                return;
            }

            IExport export;
            if (mode == Mode.Certificate) {
                export = new CertificateExport();
            } else {
                export = new PrivateKeyExport();
            }

            try {
                var container = VipNetContainer.LoadFromFile(file);
                export.Export(container, pin, Console.OpenStandardOutput());
            } catch (Exception e) {
                Console.Error.WriteLine(e.Message);
            }
        }

        static void PrintHelp()
        {
            Console.WriteLine("Использование: extractpkey {ПАРАМЕТРЫ}");
            Console.WriteLine("Извлечение данных из контейнера VipNet");
            Console.WriteLine();
            Console.WriteLine("Параметры:");
            options.WriteOptionDescriptions(Console.Out);
        }
    }
}
