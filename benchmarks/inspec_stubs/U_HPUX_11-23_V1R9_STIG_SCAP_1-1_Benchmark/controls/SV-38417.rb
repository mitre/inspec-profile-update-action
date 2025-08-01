control 'SV-38417' do
  title 'The system must prohibit the reuse of passwords within five iterations.'
  desc "If a user, or root, used the same password continuously or was allowed to change it back shortly after being forced to change it, this would provide a potential intruder with the opportunity to keep guessing at one user's password until it was guessed correctly."
  desc 'fix', 'For Trusted Mode:
Use the SAM/SMH interface or edit the /etc/default/security file and update the PASSWORD_HISTORY_DEPTH attribute. See the below example:
PASSWORD_HISTORY_DEPTH=5

If manually editing the file, save any change(s) before exiting the editor.

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Use the SAM/SMH interface (/etc/default/security file) and/or the userdbset command (/var/adm/userdb/* files) to update the PASSWORD_HISTORY_DEPTH attribute. See the below example:
PASSWORD_HISTORY_DEPTH=5

Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-4084'
  tag rid: 'SV-38417r2_rule'
  tag stig_id: 'GEN000800'
  tag gtitle: 'GEN000800'
  tag fix_id: 'F-31540r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-2, IAIA-1'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
