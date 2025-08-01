control 'SV-52483' do
  title 'The system and user default umask must be 0077 for all sessions initiated via PAM.'
  desc 'The umask controls the default access mode assigned to newly created files. An umask of 0077 limits new files to mode 0700 or less permissive. The leading zero digit represents an unsigned octal integer. This requirement applies to the globally configured system and user account defaults for all sessions initiated via PAM.'
  desc 'check', 'For Trusted Mode:
Check the attribute setting.
# grep UMASK /etc/default/security

If UMASK is not set to 0077, this is a finding.

For SMSE:
Check the attribute setting.
# grep UMASK /etc/default/security /var/adm/userdb/* 

If UMASK is not set to 0077, this is a finding.'
  desc 'fix', 'For Trusted Mode:
Use the SAM/SMH interface (/etc/default/security file) to update attribute. See the below example:
UMASK=0077

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Use the SAM/SMH interface (/etc/default/security file) and/or the userdbset command (/var/adm/userdb/* files) to update attribute. See the below example:
UMASK=0077

Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-47030r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40494'
  tag rid: 'SV-52483r1_rule'
  tag stig_id: 'GEN000000-HPUX0470'
  tag gtitle: 'GEN000000-HPUX0470'
  tag fix_id: 'F-45443r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
