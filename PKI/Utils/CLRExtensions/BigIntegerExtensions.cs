using System;
using System.Linq;
using System.Numerics;
using System.Text;

namespace PKI.Utils.CLRExtensions {
	public static class BigIntegerExtensions {
		public static Byte[] ToLittleEndianByteArray(this BigInteger bigInteger) {
			return bigInteger.ToByteArray().Reverse().ToArray();
		}
        public static void FromBitString(this BigInteger bigInteger, String bitString) {
            BigInteger res = 0;
            foreach (Char c in bitString) {
                if (c != '0' && c != '1') { throw new ArgumentException("The bit string is invalid."); }
                res <<= 1;
                res += c == '1' ? 1 : 0;
            }
            bigInteger = res;
        }
        public static string ToBinaryString(this BigInteger bigint) {
            var bytes = bigint.ToByteArray();
            var idx = bytes.Length - 1;

            // Create a StringBuilder having appropriate capacity.
            var base2 = new StringBuilder(bytes.Length * 8);

            // Convert first byte to binary.
            var binary = Convert.ToString(bytes[idx], 2);

            // Ensure leading zero exists if value is positive.
            if (binary[0] != '0' && bigint.Sign == 1) {
                base2.Append('0');
            }

            // Append binary string to StringBuilder.
            base2.Append(binary);

            // Convert remaining bytes adding leading zeros.
            for (idx--; idx >= 0; idx--) {
                base2.Append(Convert.ToString(bytes[idx], 2).PadLeft(8, '0'));
            }

            return base2.ToString();
        }
        public static BigInteger GetEnabledBitCount(this BigInteger bigInteger, Boolean ones = true) {
            BigInteger count = 0;
            BigInteger internalValue = bigInteger;
            while (internalValue > 0) {
                count += internalValue & 1;
                internalValue >>= 1;
            }
            return count;
        }
    }
}
