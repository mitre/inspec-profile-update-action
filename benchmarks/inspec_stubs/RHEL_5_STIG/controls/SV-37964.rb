control 'SV-37964' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS certificate authority file and/or directory (as appropriate) must not have an extended ACL.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'fix', 'Remove the extended ACL from the certificate file.

Procedure:
For each certificate file found remove all extended permissions

# setfacl --remove-all <certpath>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22566'
  tag rid: 'SV-37964r1_rule'
  tag stig_id: 'GEN008200'
  tag gtitle: 'GEN008200'
  tag fix_id: 'F-32461r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
