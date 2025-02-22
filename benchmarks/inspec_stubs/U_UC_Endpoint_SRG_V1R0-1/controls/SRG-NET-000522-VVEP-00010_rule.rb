control 'SRG-NET-000522-VVEP-00010_rule' do
  title 'For accounts using password or PINs for authentication, the Unified Communications Endpoint must store only cryptographic representations of passwords.'
  desc %q(If passwords and PINs are not encrypted when stored, they may be read if the storage location is compromised. 

Note that DOD requires the use two-factor, CAC-enabled authentication and the use of passwords incurs a permanent finding. Passwords should be used only in limited situations.

Examples of situations where a user ID and password might be used include:

- When the user does not use a CAC and is not a current DOD employee, member of the military, or DOD contractor.

- When a user has been officially designated as temporarily unable to present a CAC for some reason (lost, damaged, not yet issued, broken card reader) (i.e., Temporary Exception User) and to satisfy urgent organizational needs must be temporarily permitted to use user ID/password authentication until the problem with CAC use has been remedied.

- When the application is publicly available and/or hosting publicly releasable data requiring some degree of need-to-know protection.

If the password is already encrypted and not a plaintext password, this meets this requirement. Implementation of this requirement requires configuration of FIPS-approved cipher block algorithm and block cipher modes for encryption. This method uses a one-way hashing encryption algorithm with a salt value to validate a user's password without having to store the actual password. Performance and time required to access are factors that must be considered, and the one-way hash is the most feasible means of securing the password and providing an acceptable measure of password security.

Verify the user knows a password is performed using a password verifier. In its simplest form, a password verifier is a computational function that is capable of creating a hash of a password and determining if the value provided by the user matches the hash. A more secure version of verifying a user knowing a password is to store the result of an iterating hash function and a large random salt value as follows:

H0 = H(pwd, H(salt))
Hn = H(Hn-1,H(salt))

In the above, "n" is a cryptographically strong random [*3] number. "Hn" is stored along with the salt. When the application wishes to verify that the user knows a password, it simply repeats the process and compares "Hn" with the stored "Hn". A salt is essentially a fixed-length cryptographically strong random value.

Another method is using a keyed hash message authentication code (HMAC). HMAC calculates a message authentication code via a cryptographic hash function used in conjunction with an encryption key. The key must be protected as with any private key.

This requirement applies to all accounts including authentication server; Authentication, Authorization, and Accounting (AAA), and local accounts, including the root account, and the account of last resort.)
  desc 'check', 'Verify the Unified Communications Endpoint, when using passwords or PINs for authentication, stores cryptographic representations of passwords. 

If the Unified Communications Endpoint, when using passwords or PINs for authentication, does not store cryptographic representations of passwords, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint, when using passwords or PINs for authentication, to store cryptographic representations of passwords.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000522-VVEP-00010_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000522-VVEP-00010'
  tag rid: 'SRG-NET-000522-VVEP-00010_rule'
  tag stig_id: 'SRG-NET-000522-VVEP-00010'
  tag gtitle: 'SRG-NET-000522-VVEP-00010'
  tag fix_id: 'F-SRG-NET-000522-VVEP-00010_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
