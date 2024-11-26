control 'SV-38276' do
  title 'The system must enforce the correctness of the entire password during authentication.'
  desc "Some common password hashing schemes only process the first eight characters of a user's password, which reduces the effective strength of the password."
  desc 'check', 'Note that in certain instances, the password field of any given password database may present as "*" or "!!", indicating that the account is locked or disabled.

For Trusted Mode:
Verify that password hashes in /tcb do not begin with a character other than a dollar sign ($).
# cd /tcb/files/auth && cat */* | egrep ":u_name=|:u_pwd="

If user account password hashes begins with any character other than a dollar sign ($), this is a finding.

For SMSE:
Verify that password hashes in /etc/shadow do not begin with a character other than a dollar sign ($).
# cat /etc/shadow | cut -f 2,2 -d ":" | egrep -v "^\\\\$|\\\\*|\\\\!\\\\!"

If any password hash without a leading dollar sign is returned by the above command, this is a finding.'
  desc 'fix', 'For Trusted Mode:
NOTE: There is no fix for Trusted Mode/Systems (TS). MD5 is currently used, and according vendor documentation, this algorithm will not be updated, due to TS being deprecated after HP-UX 11i-v2 (11.23). 

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Use the SAM/SMH interface (/etc/default/security file) to update the attribute. See the below example:
CRYPT_DEFAULT=6

Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-47032r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22302'
  tag rid: 'SV-38276r2_rule'
  tag stig_id: 'GEN000585'
  tag gtitle: 'GEN000585'
  tag fix_id: 'F-45445r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
