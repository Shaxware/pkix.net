namespace PKI.Security {
	/// <summary>
	/// Represents a simplified version of Active Directory object's access control list (ACL).
	/// </summary>
	/// <remarks>This class is marked for deletion. A new constructions will be available.</remarks>
	public class SecurityDescriptor2 {
		/// <summary>
		/// Gets the distinguished name of the object.
		/// </summary>
		public string Path { get; set; }
		/// <summary>
		/// Gets the owner of the object.
		/// </summary>
		public string Owner { get; set; }
		/// <summary>
		/// Gets a collection of access control entries (ACE).
		/// </summary>
		public AccessControlEntry2[] Access { get; set; }
	}
}
