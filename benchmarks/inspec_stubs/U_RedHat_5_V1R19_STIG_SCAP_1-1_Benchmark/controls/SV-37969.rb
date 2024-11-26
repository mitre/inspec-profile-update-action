control 'SV-37969' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS key file must be owned by root.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'fix', 'Change the ownership of the file.
# chown root <keypath>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22571'
  tag rid: 'SV-37969r1_rule'
  tag stig_id: 'GEN008300'
  tag gtitle: 'GEN008300'
  tag fix_id: 'F-32503r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
