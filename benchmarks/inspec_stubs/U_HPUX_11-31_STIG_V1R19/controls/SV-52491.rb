control 'SV-52491' do
  title 'The password hashes stored on the system must have been generated using a FIPS 140-2 approved cryptographic hashing algorithm.'
  desc 'Systems must employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2 approved successors.  The use of unapproved algorithms may result in weak password hashes that are more vulnerable to compromise.'
  desc 'check', 'Note that in certain instances, the password field of any given password database may present as “*” or “!!”, indicating that the account is locked or disabled.

For Trusted Mode:
Verify that the first 3 characters in the /tcb password hashes begin with the characters “$6$” (note that double quotes are for emphasis only).
# cd /tcb/files/auth && cat */* | egrep “:u_name=|:u_pwd=“

If user account password hashes begins with any characters other than “$6$”, this is a finding.

For SMSE:
Verify that password hashes in /etc/shadow begin with the characters “$6$” (note that double quotes are for emphasis only).
# cat /etc/shadow | cut -f 2,2 -d “:” | egrep -v “^\\\\*|\\\\!\\\\!”

If user account password hashes begins with any characters other than “$6$”, this is a finding.'
  desc 'fix', 'For Trusted Mode:
NOTE: There is no fix for Trusted Mode/Systems (TS). MD5 is currently used, and per vendor documentation, this algorithm will not be updated, due to TS being deprecated/replaced by SMSE. This will always result in a finding.

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Use the SAM/SMH interface (/etc/default/security file) to update the attribute. See the below example:
CRYPT_ALGORITHMS_DEPRECATE=__unix__
CRYPT_DEFAULT=6

Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-47037r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22304'
  tag rid: 'SV-52491r2_rule'
  tag stig_id: 'GEN000595'
  tag gtitle: 'GEN000595'
  tag fix_id: 'F-45450r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
