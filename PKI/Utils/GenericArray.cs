using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace PKI.Utils {
	static class GenericArray {
		public static Boolean CompareArray<T>(T[] array1, T[] array2) {
			if (ReferenceEquals(array1, array2)) { return true; }
			if (array1 == null || array2 == null) { return false; }
			if (array1.Length != array2.Length) { return false; }
			EqualityComparer<T> comparer = EqualityComparer<T>.Default;
			for (Int64 index = 0; index < array1.Length; index++) {
				if (!comparer.Equals(array1[index], array2[index])) { return false; }
			}
			return true;
		}
		public static T[] GetUniques<T>(IEnumerable<T> source) {
			List<T> uniques = new List<T>();
			foreach (T item in source.Where(item => !uniques.Contains(item))) {
				uniques.Add(item);
			}
			return uniques.ToArray();
		}
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
		[Obsolete]
		public static Byte[] HexStringToArray(String str) {
			if (str.Length % 2 == 1) { str = "0" + str; }
			return Enumerable.Range(0, str.Length)
					 .Where(x => x % 2 == 0)
					 .Select(x => Convert.ToByte(str.Substring(x, 2), 16))
					 .ToArray();

		}
	}
}