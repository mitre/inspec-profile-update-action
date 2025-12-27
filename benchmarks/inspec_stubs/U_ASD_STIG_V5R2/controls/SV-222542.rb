control 'SV-222542' do
  title 'The application must only store cryptographic representations of passwords.'
  desc "Use of passwords for application authentication is intended only for limited situations and should not be used as a replacement for two-factor CAC-enabled authentication.

Examples of situations where a user ID and password might be used include but are not limited to:

- When the application user base does not have a CAC and is not a current DoD employee, member of the military, or a DoD contractor.

- When an application user has been officially designated as a Temporary Exception User; one who is temporarily unable to present a CAC for some reason (lost, damaged, not yet issued, broken card reader) and to satisfy urgent organizational needs must be temporarily permitted to use user ID/password authentication until the problem with CAC use has been remedied.

and

- When the application is publicly available and or hosting publicly releasable data requiring some degree of need-to-know protection.

Passwords need to be protected at all times and using a strong one-way hashing encryption algorithm with a salt is the standard method for providing a means to validate a user's password without having to store the actual password.  

Performance and time required to access are factors that must be considered and the one way hash is the most feasible means of securing the password and providing an acceptable measure of password security.  If passwords are stored in clear text, they can be plainly read and easily compromised.

In many instances, verifying the user knows a password is performed using a password verifier. In its simplest form, a password verifier is a computational function that is capable of creating a hash of a password and determining if the value provided by the user matches the hash.  

A more secure version of verifying a user knowing a password is to store the result of an iterating hash function and a large random SALT value as follows:

H0 = H(pwd, H(salt))
Hn = H(Hn-1,H(salt))

Where n is a cryptographically-strong random [*3] number. Hn is stored, along with the salt. When the application wishes to verify that the user knows a password, it simply repeats the process and compares Hn with the stored Hn.

A SALT is essentially a fixed-length cryptographically-strong random value.  

Another method used is utilizing a keyed hash message authentication code (HMAC).  HMAC calculates a message authentication code via a cryptographic hash function used in conjunction with an encryption key.  The key must be protected as with any private key.
 
Applications must only store passwords that have been cryptographically protected."
  desc 'check', "Review the application documentation and interview the application administrator to identify if the application uses passwords for user authentication.

If the application does not use passwords, the requirement is not applicable.

Have the application administrator identify the application's password storage locations.  Potential locations include the local file system where the application is stored or in an application-related database table that should not be accessible to application users.

Review application files and folders using a text editor or by using a database tool that allows you to view data stored in database tables.  Look for indications of stored user information and review that information.  Determine if password strings are readable/discernable.

Determine if the application uses the MD5 hashing algorithm to create password hashes.

If the passwords are readable or there is no indication the application utilizes cryptographic hashing to protect passwords, or if the MD5 hash algorithm is used to create password hashes, this is a finding."
  desc 'fix', 'Use strong cryptographic hash functions when creating password hash values.

Utilize random salt values when creating the password hash.

Ensure strong access control permissions on data files containing authentication data.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24212r493534_chk'
  tag severity: 'high'
  tag gid: 'V-222542'
  tag rid: 'SV-222542r508029_rule'
  tag stig_id: 'APSC-DV-001740'
  tag gtitle: 'SRG-APP-000171'
  tag fix_id: 'F-24201r493535_fix'
  tag 'documentable'
  tag legacy: ['V-69567', 'SV-84189']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
