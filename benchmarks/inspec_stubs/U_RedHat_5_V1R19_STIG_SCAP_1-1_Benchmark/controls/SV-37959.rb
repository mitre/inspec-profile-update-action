control 'SV-37959' do
  title 'If the system is using LDAP for authentication or account information, the TLS certificate authority file and/or directory (as appropriate) must be owned by root.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'fix', 'Change the ownership of the file or directory.
# chown root <certpath>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22563'
  tag rid: 'SV-37959r3_rule'
  tag stig_id: 'GEN008140'
  tag gtitle: 'GEN008140'
  tag fix_id: 'F-32446r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
