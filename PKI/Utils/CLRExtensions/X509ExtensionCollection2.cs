using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace PKI.Utils.CLRExtensions {
	static class X509ExtensionCollection2 {
		public static X509Extension[] ToArray(this X509ExtensionCollection exts) {
			if (exts == null) { return null; }
			List<X509Extension> e = new List<X509Extension>(exts.Cast<X509Extension>());
			return e.ToArray();
		}
		public static void AddRange(this X509ExtensionCollection exts, IEnumerable<X509Extension> extensions) {
			if (exts == null) { return; }
			foreach (X509Extension e in extensions) {
				exts.Add(e);
			}
		}
		public static void Remove(this X509ExtensionCollection exts, String oid) {
			if (exts == null) { return; }
			for (Int32 i = 0; i < exts.Count; i++) {
				if (exts[i].Oid.Value == oid) {
					exts.RemoveAt(i);
					return;
				}
			}
		}
		public static void RemoveAt(this X509ExtensionCollection exts, Int32 index) {
			if (exts == null || index >= exts.Count) { return; }
			List<X509Extension> e = new List<X509Extension>(exts.Cast<X509Extension>());
			e.RemoveAt(index);
			exts = new X509ExtensionCollection();
			foreach (X509Extension ext in e) {
				exts.Add(ext);
			}
		}
		public static Int32 IndexOf(this X509ExtensionCollection exts, X509Extension extension) {
			if (exts == null) { return -1; }
			for (Int32 i = 0; i < exts.Count; i++) {
				if (exts[i].Oid.Value == extension.Oid.Value) { return i; }
			}
			return -1;
		}
		public static void Insert(this X509ExtensionCollection exts, Int32 index, X509Extension extension ) {
			if (extension == null) { throw new ArgumentNullException("extension"); }
			if (exts == null) { return; }
			if (index < 0 || index >= exts.Count) { throw new OverflowException(); }
			List<X509Extension> e = new List<X509Extension>(exts.Cast<X509Extension>());
			e.Insert(index, extension);
			exts = new X509ExtensionCollection();
			exts.AddRange(e);
		}
	}
}
