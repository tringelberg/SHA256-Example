using System.Diagnostics;

namespace SHA256_Example.Classes
{
    public class MySHA256
    {
        private const int BufferSize = 8192;
        private uint[] H;
        private uint[] W;
        private uint a, b, c, d, e, f, g, h;
        private long _messageLength;
        private long _messageOffset;
        private bool _appliedPadding;

        private readonly uint[] K =
        {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        public string ComputeHash(Stream stream)
        {
            int bytesRead;
            byte[] buffer;

            Debug.Assert(BufferSize >= 64 || BufferSize % 64 == 0);

            _messageLength = stream.Length;
            _messageOffset = 0;
            _appliedPadding = false;
            buffer = new byte[BufferSize];

            InitializeHash();

            do
            {
                bytesRead = stream.Read(buffer, 0, BufferSize);
                _messageOffset += bytesRead;

                ProcessBlock(buffer.Take(bytesRead).ToArray());

            } while (bytesRead > 0 && !_appliedPadding);

            return GetHashString();
        }

        private void ProcessBlock(byte[] block)
        {
            if (_messageOffset == _messageLength)
            {
                block = PadBytes(block);
                _appliedPadding = true;
            }

            foreach (byte[] chunk in block.Chunk(64))
            {
                Hash64Bytes(chunk);
            }
        }

        private void InitializeHash()
        {
            H = new uint[]
            {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            };
        }

        private void Hash64Bytes(byte[] bytes64)
        {
            PrepareMessageSchedule(bytes64);
            InitializeWorkingVariables();
            PerformHashComputation();
            ComputeIntermediateHashValue();
        }

        private void PrepareMessageSchedule(byte[] bytes)
        {
            uint[] words;

            W = new uint[64];
            words = bytes.Chunk(4).Select(ToUint32).ToArray();

            Array.Copy(words, W, 16);

            for (int t = 16; t < 64; t++)
            {
                W[t] = SSIG1(W[t - 2]) + W[t - 7] + SSIG0(W[t - 15]) + W[t - 16];
            }
        }

        private void InitializeWorkingVariables()
        {
            a = H[0];
            b = H[1];
            c = H[2];
            d = H[3];
            e = H[4];
            f = H[5];
            g = H[6];
            h = H[7];
        }

        private void PerformHashComputation()
        {
            uint T1, T2;

            for (int t = 0; t < 64; t++)
            {
                T1 = h + BSIG1(e) + CH(e, f, g) + K[t] + W[t];
                T2 = BSIG0(a) + MAJ(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            }
        }

        private void ComputeIntermediateHashValue()
        {
            uint[] tempHash = new uint[8];

            tempHash[0] = a + H[0];
            tempHash[1] = b + H[1];
            tempHash[2] = c + H[2];
            tempHash[3] = d + H[3];
            tempHash[4] = e + H[4];
            tempHash[5] = f + H[5];
            tempHash[6] = g + H[6];
            tempHash[7] = h + H[7];

            Array.Copy(tempHash, H, tempHash.Length);
        }

        private byte[] PadBytes(byte[] message)
        {
            int paddingCount = 0;
            byte[] paddedMessage;

            while ((message.Length + ++paddingCount) % 64 != 56) ;

            paddedMessage = new byte[message.Length + paddingCount + 8];
            Array.Copy(message, paddedMessage, message.Length);

            paddedMessage[message.Length] |= 0x80;
            Array.Copy(ToByteArray(_messageLength * 8), 0, paddedMessage, message.Length + paddingCount, 8);

            return paddedMessage;
        }

        private byte[] ToByteArray(long number)
        {
            byte[] byteArray = new byte[8];

            for (int i = 0; i < 8; i++)
            {
                byteArray[7 - i] = (byte)((number >> (8 * i)) & 0xFF);
            }

            return byteArray;
        }

        private uint ToUint32(byte[] bytes)
        {
            uint number = 0;

            for (int i = 1; i <= 4; i++)
            {
                number |= (uint)bytes[i - 1] << (8 * (4 - i));
            }

            return number;
        }

        private string GetHashString()
            => string.Concat(H.Select(h => Convert.ToString(h, 16).PadLeft(8, '0')));

        private uint RotR(uint num, int shiftCount)
            => (num >> shiftCount) | (num << (32 - shiftCount));

        private uint CH(uint x, uint y, uint z)
            => (x & y) ^ ((~x) & z);

        private uint MAJ(uint x, uint y, uint z)
            => (x & y) ^ (x & z) ^ (y & z);

        private uint BSIG0(uint x)
            => RotR(x, 2) ^ RotR(x, 13) ^ RotR(x, 22);

        private uint BSIG1(uint x)
            => RotR(x, 6) ^ RotR(x, 11) ^ RotR(x, 25);

        private uint SSIG0(uint x)
            => RotR(x, 7) ^ RotR(x, 18) ^ (x >> 3);

        private uint SSIG1(uint x)
            => RotR(x, 17) ^ RotR(x, 19) ^ (x >> 10);
    }
}
