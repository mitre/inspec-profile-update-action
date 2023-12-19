control 'SV-38245' do
  title 'The system must require passwords contain at least one numeric character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'For Trusted Mode:
Check the PASSWORD_MIN_DIGIT_CHARS setting.
# cat /etc/default/security | grep PASSWORD_MIN_DIGIT_CHARS 

If PASSWORD_MIN_DIGIT_CHARS is not set to 1 or greater this is a finding.

For SMSE:
Check the PASSWORD_MIN_DIGIT_CHARS setting.
# grep PASSWORD_MIN_DIGIT_CHARS /etc/default/security /var/adm/userdb/*

If PASSWORD_MIN_DIGIT_CHARS is not set to 1 or greater, this is a finding.'
  desc 'fix', 'For Trusted Mode:
Use the SAM/SMH interface or edit the /etc/default/security file and update the PASSWORD_MIN_DIGIT_CHARS attribute. See the below example:
PASSWORD_MIN_DIGIT_CHARS=1

If manually editing the file, save any change(s) before exiting the editor.

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Use the SAM/SMH interface (/etc/default/security file) and/or the userdbset command (/var/adm/userdb/* files) to update the PASSWORD_MIN_DIGIT_CHARS attribute. See the below example:
PASSWORD_MIN_DIGIT_CHARS=1

Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36285r2_chk'
  tag severity: 'medium'
  tag gid: 'V-11972'
  tag rid: 'SV-38245r2_rule'
  tag stig_id: 'GEN000620'
  tag gtitle: 'GEN000620'
  tag fix_id: 'F-31542r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-2, IAIA-1'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
