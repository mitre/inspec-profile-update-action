control 'SV-26961' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS key file must not have an extended ACL.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', %q(Determine the key file.
# grep -i '^tls_key' /etc/ldap.conf
Check the permissions.
# ls -lL <keypath>
If the permissions of the file contains a "+", an extended ACL is present, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the key file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27908r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22574'
  tag rid: 'SV-26961r1_rule'
  tag stig_id: 'GEN008360'
  tag gtitle: 'GEN008360'
  tag fix_id: 'F-24223r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
