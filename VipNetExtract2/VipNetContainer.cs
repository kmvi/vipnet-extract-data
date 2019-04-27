using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Org.BouncyCastle.Asn1;

namespace VipNetExtract
{
    class VipNetContainer
    {
        private VipNetContainer(
            string type, uint version, int headerSize,
            byte[] header, IList<VipNetContainerEntry> entries)
        {
            Type = type;
            Version = version;
            HeaderSize = headerSize;
            Header = header;
            Entries = entries;
        }

        public string Type { get; }
        public uint Version { get; }
        public int HeaderSize { get; }
        public byte[] Header { get; }
        public IList<VipNetContainerEntry> Entries { get; }

        public static VipNetContainer LoadFromStream(Stream strm)
        {
            using (var reader = new BinaryReader(strm)) {
                var type = Encoding.ASCII.GetString(reader.ReadBytes(4));
                if (type != "ITCS" && type != "PKEY" && type != "_CCK" && type != "_LCK")
                    throw new NotSupportedException($"Неподдерживаемый тип контейнера: {type}.");

                var version = reader.ReadUInt32();
                if (LoWord(version) > 0xFF || HiWord(version) > 2)
                    throw new NotSupportedException($"Неподдерживаемая версия контейнера: {version}.");

                var headerSize = reader.ReadInt32();
                var header = new byte[headerSize];
                if (headerSize > 0)
                    header = reader.ReadBytes(headerSize);

                var entries = new List<VipNetContainerEntry>();
                while (strm.Position < strm.Length) {
                    var entrySize = reader.ReadInt32();
                    var entryStartPos = strm.Position;
                    var entrySeq = (Asn1Sequence)Asn1Object.FromStream(strm);
                    var keySize = reader.ReadInt32();
                    if (keySize < 0 || strm.Position + keySize - entryStartPos != entrySize)
                        throw new InvalidOperationException($"Некорректный размер блока с ключом: {keySize}.");
                    var key = reader.ReadBytes(keySize);
                    entries.Add(new VipNetContainerEntry(entrySeq, key));
                }

                if (entries.Count == 0)
                    throw new InvalidOperationException("Контейнер не содержит записей.");

                return new VipNetContainer(type, version, headerSize, header, entries);
            }
        }

        public static VipNetContainer LoadFromFile(string fileName)
        {
            using (var strm = File.OpenRead(fileName))
                return LoadFromStream(strm);
        }

        static uint LoWord(uint x) => x & 0x0000FFFF;
        static uint HiWord(uint x) => x >> 16;
    }
}
