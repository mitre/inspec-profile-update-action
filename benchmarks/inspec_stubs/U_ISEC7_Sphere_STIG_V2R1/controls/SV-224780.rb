control 'SV-224780' do
  title 'The Apache Tomcat Manager Web app password must be cryptographically hashed with a DoD approved algorithm.'
  desc %q(The Apache Tomcat Manager Web app password is stored in plain text in CATALINA_HOME/conf/tomcat-users.xml and should be encrypted so it is not visible to an intruder. 

Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read and easily compromised. Use of passwords for authentication is intended only for limited situations and should not be used as a replacement for two-factor CAC-enabled authentication. 

Examples of situations where a user ID and password might be used include:

- When the user does not use a CAC and is not a current DoD employee, member of the military, or DoD contractor.

- When a user has been officially designated as temporarily unable to present a CAC for some reason (lost, damaged, not yet issued, broken card reader) (i.e., Temporary Exception User) and to satisfy urgent organizational needs must be temporarily permitted to use user ID/password authentication until the problem with CAC use has been remedied.

- When the application is publicly available and or hosting publicly releasable data requiring some degree of need-to-know protection.

If the password is already encrypted and not a plaintext password, this meets this requirement. Implementation of this requirement requires configuration of FIPS-approved cipher block algorithm and block cipher modes for encryption. This method uses a one-way hashing encryption algorithm with a salt value to validate a user's password without having to store the actual password. Performance and time required to access are factors that must be considered, and the one-way hash is the most feasible means of securing the password and providing an acceptable measure of password security.

Verifying the user knows a password is performed using a password verifier. In its simplest form, a password verifier is a computational function that is capable of creating a hash of a password and determining if the value provided by the user matches the hash. A more secure version of verifying a user knowing a password is to store the result of an iterating hash function and a large random salt value as follows:

H0 = H(pwd, H(salt))
Hn = H(Hn-1,H(salt))

In the above, "n" is a cryptographically-strong random [*3] number. "Hn" is stored along with the salt. When the application wishes to verify that the user knows a password, it simply repeats the process and compares "Hn" with the stored "Hn". A salt is essentially a fixed-length cryptographically strong random value.

Another method is using a keyed-hash message authentication code (HMAC). HMAC calculates a message authentication code via a cryptographic hash function used in conjunction with an encryption key. The key must be protected as with any private key.

This requirement applies to all accounts including authentication server, AAA, and local account, including the root account and the account of last resort.)
  desc 'check', 'Verify the Apache Tomcat Manager Web app password is hashed using SHA-256 (or SHA-512).

Login to the ISEC7 EMM Suite server.
Navigate to <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\conf\\
Open tomcat-users.xml and verify the user password has been hashed with an obfuscated password.

ex: <user password="310c55aa3d5b42217e7f0e80ce30467d$100000$529cceb1fbc80f4f461fc1bd56219d79d9c94d4a8fc46abad0646f27e753ff9e" roles="manager-gui,manager-script" username="admin"/>

Open <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\conf\\server.xml with Notepad.exe

Select Edit >> Find and search for CredentialHandler.

Confirm the text: <CredentialHandler algorithm="PBKDF2WithHmacSHA512" keyLength="256" />

Close the file.

If the Apache Tomcat Manager Web app password is not hashed using SHA-256 (or SHA-512), this is a finding.'
  desc 'fix', 'To encrypt the Tomcat Manager Web app password, run the ISEC7 integrated installer or use the following manual procedure.

Note: The ISEC7 integrated installer will configure SHA-512 as the hash algorithm, which is not available with the manual procedure. The manual procedure will configure SHA-256. Both are DoD approved.

Login to the ISEC7 EMM Suite server.
Browse to <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\conf and open Tomcat-Users.xml
Open the Command Prompt and CD to <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\bin
Execute the following command:

digest -a SHA-256 -h org.apache.catalina.realm.MessageDigestCredentialHandler *

*where password is the 15 character password designated for the account

Copy the output, which is the SHA-256 hashed digest password.
In Tomcat-Users.xml, add in the password for the user with the obfuscated output.

ex: <user password="310c55aa3d5b42217e7f0e80ce30467d$100000$529cceb1fbc80f4f461fc1bd56219d79d9c94d4a8fc46abad0646f27e753ff9e" roles="manager-gui,manager-script" username="admin"/>

Save the file.

Open <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\conf\\server.xml with Notepad.exe
Select Edit >> Find and search for CredentialHandler.
Replace the text with:  <CredentialHandler className="org.apache.catalina.realm.MessageDigestCredentialHandler" algorithm="SHA-256" />
Save the file.
Restart the ISEC7 EMM Suite Web service using the services.msc'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26471r461596_chk'
  tag severity: 'medium'
  tag gid: 'V-224780'
  tag rid: 'SV-224780r505933_rule'
  tag stig_id: 'ISEC-06-550150'
  tag gtitle: 'SRG-APP-000171'
  tag fix_id: 'F-26459r461597_fix'
  tag 'documentable'
  tag legacy: ['SV-106381', 'V-97275']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
