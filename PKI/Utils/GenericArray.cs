using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace PKI.Utils {
	static class GenericArray {
		public static Boolean OidContains(Oid[] source, Oid oid) {
			if (source.Length == 0) { return false; }
			foreach (Oid item in source) {
				if (String.IsNullOrEmpty(oid.FriendlyName)) {
					if (item.Value == oid.Value) { return true; }
				} else {
					if (item.FriendlyName == oid.FriendlyName) { return true; }
				}
			}
			return false;
		}
		public static void RemoveOid(ref List<Oid> source, Oid oid) {
			for (Int32 index = 0; index < source.Count; index++) {
				if (String.IsNullOrEmpty(oid.FriendlyName)) {
					if (source[index].Value == oid.Value) { source.RemoveAt(index); index--; }
				} else {
					if (source[index].FriendlyName == oid.FriendlyName) { source.RemoveAt(index); index--; }
				}
			}
		}
		public static void ReverseOrder(ref Byte[] array) {
			for (Int32 index = 0; index < array.Length; index += 2) {
				Byte temp = array[index];
				array[index] = array[index + 1];
				array[index + 1] = temp;
			}
		}
	}
}