control 'SV-38448' do
  title 'The system must not have accounts configured with blank or null passwords.'
  desc 'If an account is configured for password authentication but does not have an assigned password, it may be possible to log into the account without authentication. If the root user is configured without a password, the entire system may be compromised. For user accounts not using password authentication, the account must be configured with a password lock value instead of a blank or null value.'
  desc 'fix', 'For Trusted Mode:
Use the System Administration Manager (SAM) or the System Management Homepage (SMH) to disable null passwords and immediately expire the password for any account with a null password, forcing the user to create a password on the very next login. Alternatively, the account may also be disabled.

Protected password database files are maintained in the /tcb/files/auth hierarchy. This directory contains other directories each named with a single letter from the alphabet. User authentication profiles are stored in these directories based on the first letter of the user account name. 
Verify that SAM/SMH has now disabled null passwords for all accounts.
# grep “:u_nullpw@:” /tcb/files/auth/[a-z,A-Z]

For SMSE:
Use the SAM/SMH interface (/etc/default/security file) and/or the userdbset command (/var/adm/userdb/* files) to update the attribute(s). See the below example:
LOGIN_POLICY_STRICT=1
ALLOW_NULL_PASSWORD=0

Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor. Use the System Administration Manager (SAM) or the System Management Homepage (SMH) to immediately expire the password for any account with a null password, forcing the user to create a password on the very next login. Alternatively, the account may also be disabled.'
  impact 0.7
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'high'
  tag gid: 'V-770'
  tag rid: 'SV-38448r2_rule'
  tag stig_id: 'GEN000560'
  tag gtitle: 'GEN000560'
  tag fix_id: 'F-31509r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
