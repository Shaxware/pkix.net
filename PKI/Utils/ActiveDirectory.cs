using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net;
using System.Text;

namespace PKI.Utils {
	static class ActiveDirectory {
		const String disallowed = @"!""#%&'()*+,/:;<=>?[\]^`{|}";
		public static String ConfigContext {
			get {
				if (Ping()) {
					DirectoryEntry entry = new DirectoryEntry("LDAP://RootDSE");
					return (String)entry.Properties["ConfigurationNamingContext"].Value;
				}
				return null;
			}
		}
		public static Boolean Ping() {
			try {
				String domain = Domain.GetCurrentDomain().Name;
				return !String.IsNullOrEmpty(domain);
			} catch { return false; }
		}
		public static DirectoryEntries GetChildItems(String ldap) {
			DirectoryEntry entry = new DirectoryEntry("LDAP://" + ldap);
			return entry.Children;
		}
		public static String BindServerToSite(String computerName) {
			if (String.IsNullOrEmpty(computerName)) { return null; }
			Hashtable siteTable = new Hashtable();
			IPHostEntry ip = Dns.GetHostEntry(computerName);

			try {
				DirectoryEntry subnets = new DirectoryEntry("LDAP://CN=Subnets,CN=Sites," + ConfigContext);
				foreach (DirectoryEntry subnet in subnets.Children) {
					DirectoryEntry site = new DirectoryEntry("LDAP://" + subnet.Properties["siteObject"].Value);
					siteTable.Add(subnet.Properties["cn"].Value, site.Properties["cn"].Value);
				}
			} catch {
				return null;
			}
			return (from string key in siteTable.Keys let tokens = key.Split('/') where ip.AddressList.Any(address => Networking.InSameSubnet(tokens[0], Convert.ToInt32(tokens[1]), address.ToString())) select (String)siteTable[key]).FirstOrDefault();
		}
		public static String GetSanitizedName(String fullName) {
			const Int32 maxLength = 51;
			StringBuilder sanitizedBuilder = fullName.Aggregate(new StringBuilder(),
												 (SB, c) => isAllowedCharacter(c)
													 ? SB.Append(c)
													 : SB.Append('!').Append(((Int32)c).ToString("x4")));

			String sanitizedString = sanitizedBuilder.ToString();
			if (sanitizedString.Length <= maxLength) return sanitizedString;

			String testForIncompleteSequence = sanitizedString.Substring(maxLength - 4, 4);
			Int32 i = testForIncompleteSequence.IndexOf('!');
			Int32 splitPosition = i < 0
				? maxLength
				: maxLength - 4 + i;
			String exceeded = sanitizedString.Substring(splitPosition);
			String truncated = sanitizedString.Remove(splitPosition);
			return truncated + "-" + getExceedHash(exceeded);
		}

		static Boolean isAllowedCharacter(Char c) {
			return (c >= 0x20 && c <= 0x79) && !disallowed.Contains(c);
		}
		static String getExceedHash(IEnumerable<Char> str) {
			unchecked {
				UInt16 hash = str.Aggregate((UInt16)0, (h, c) => {
					UInt16 lowBit = (h & 0x8000) == 0 ? (UInt16)0 : (UInt16)1;
					return (UInt16)(((h << 1) | lowBit) + c);
				});
				return hash.ToString("d5");
			}
		}
	}
}
