control 'SV-46041' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS key file must have mode 0600 or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.

Note:  Depending on the particular implementation, group and other read permission may be necessary for unprivileged users to successfully resolve account information using LDAP.  This will still be a finding, as these permissions provide users with access to system authenticators.'
  desc 'check', "Determine the key file.
# grep -i '^tls_key' /etc/ldap.conf
Check the permissions.
# ls -lL <keypath>
If the mode of the file is more permissive than 0600, this is a finding."
  desc 'fix', 'Change the mode of the file.
# chmod 0600 <keypath>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43312r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22573'
  tag rid: 'SV-46041r1_rule'
  tag stig_id: 'GEN008340'
  tag gtitle: 'GEN008340'
  tag fix_id: 'F-39401r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
