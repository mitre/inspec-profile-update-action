control 'SV-38445' do
  title 'The system must disable accounts after three consecutive unsuccessful login attempts.'
  desc 'Disabling accounts after a limited number of unsuccessful login attempts improves protection against password guessing attacks.'
  desc 'check', 'For Trusted Mode:
The u_maxtries attribute in the /tcb/files/auth/system/default file controls whether an account is locked after too many consecutive authentication failures. An account is locked after “N” consecutive authentication failures. Check the global setting for u_maxtries is set to N=3.
# grep u_maxtries /tcb/files/auth/system/default 

If the u_maxtries attribute is not set to 3, this is a finding.

For SMSE:
The AUTH_MAXTRIES attribute in the /etc/default/security configuration file controls whether an account is locked after too many consecutive authentication failures. An account is locked after N+1 consecutive authentication failures. Check the setting for AUTH_MAXTRIES is set to N=2.
# grep AUTH_MAXTRIES /etc/default/security /var/adm/userdb/*

If the attribute AUTH_MAXTRIES is not set to 2, this is a finding.'
  desc 'fix', 'For Trusted Mode:
Use the SAM/SMH interface or edit the /tcb/files/auth/system/default file and update the u_maxtries attribute. See the below example:
:u_maxtries#3:

If manually editing the file, save any change(s) before exiting the editor.

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Use the SAM/SMH interface (/etc/default/security file) and/or the userdbset command (/var/adm/userdb/* files) to update the attribute. See the below example:
AUTH_MAXTRIES=2

Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36249r2_chk'
  tag severity: 'medium'
  tag gid: 'V-766'
  tag rid: 'SV-38445r2_rule'
  tag stig_id: 'GEN000460'
  tag gtitle: 'GEN000460'
  tag fix_id: 'F-31506r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLO-1, ECLO-2'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
