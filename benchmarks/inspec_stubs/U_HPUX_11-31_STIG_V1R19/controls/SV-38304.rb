control 'SV-38304' do
  title 'The system must require passwords contain at least one lowercase alphabetic character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'For Trusted Mode:
Check the PASSWORD_MIN_LOWER_CASE_CHARS setting.
# cat /etc/default/security | grep PASSWORD_MIN_LOWER_CASE_CHARS 

If PASSWORD_MIN_LOWER_CASE_CHARS is not set to 1 or greater, this is a finding.

For SMSE:
Check the PASSWORD_MIN_LOWER_CASE_CHARS setting.
# grep PASSWORD_MIN_LOWER_CASE_CHARS /etc/default/security /var/adm/userdb/*

If PASSWORD_MIN_LOWER_CASE_CHARS is not set to 1 or greater, this is a finding.'
  desc 'fix', 'For Trusted Mode:
Use the SAM/SMH interface or edit the /etc/default/security file and update the PASSWORD_MIN_LOWER_CASE_CHARS attribute. See the below example:
PASSWORD_MIN_LOWER_CASE_CHARS=1

If manually editing the file, save any change(s) before exiting the editor.

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Use the SAM/SMH interface (/etc/default/security file) and/or the userdbset command (/var/adm/userdb/* files) to update the PASSWORD_MIN_LOWER_CASE_CHARS attribute. See the below example:
PASSWORD_MIN_LOWER_CASE_CHARS=1

Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36292r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22305'
  tag rid: 'SV-38304r2_rule'
  tag stig_id: 'GEN000610'
  tag gtitle: 'GEN000610'
  tag fix_id: 'F-31549r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
