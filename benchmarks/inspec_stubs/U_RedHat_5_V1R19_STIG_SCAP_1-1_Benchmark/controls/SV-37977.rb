control 'SV-37977' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS key file must not have an extended ACL.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'fix', 'Remove the extended ACL from the key file.

Procedure:
For each key file found remove all extended permissions.

# setfacl --remove-all <keypath>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22574'
  tag rid: 'SV-37977r1_rule'
  tag stig_id: 'GEN008360'
  tag gtitle: 'GEN008360'
  tag fix_id: 'F-32509r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
