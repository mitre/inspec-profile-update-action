control 'SV-38199' do
  title 'Users must not be able to change passwords more than once every 24 hours.'
  desc 'The ability to change passwords frequently facilitates users reusing the same password. This can result in users effectively never changing their passwords. This would be accomplished by users changing their passwords when required and then immediately changing it to the original value.'
  desc 'check', "For Trusted Mode:
Check the “u_minchg” attribute in the users TS database entry.
Individual user:
# export PATH=$PATH:/usr/lbin
# getprpw -r -m mintm <USER>
 
All users:
# logins -o -x | awk -F: '{print $1” “$10}'

If the value is less than 1 for any user, this is a finding.

For SMSE:
Check the PASSWORD_MINDAYS attribute.
# grep PASSWORD_MINDAYS /etc/default/security /var/adm/userdb/*

If the attribute PASSWORD_MINDAYS is less than 1, this is a finding."
  desc 'fix', 'For both Trusted Mode and SMSE:
Use the SAM/SMH interface to ensure that password changes are restricted to no less than once every 24 hours.

Use the SAM/SMH interface (/etc/default/security file) and/or the userdbset command (/var/adm/userdb/* files) to ensure that password changes are restricted to no less than once every 24 hours. See the below example:
PASSWORD_MINDAYS=1

Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36255r3_chk'
  tag severity: 'medium'
  tag gid: 'V-1032'
  tag rid: 'SV-38199r2_rule'
  tag stig_id: 'GEN000540'
  tag gtitle: 'GEN000540'
  tag fix_id: 'F-31512r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
