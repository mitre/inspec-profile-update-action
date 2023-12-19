control 'SV-37956' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf (or equivalent) file must not have an extended ACL.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'fix', 'Remove the extended ACL from the "/etc/ldap.conf" file.
# setfacl --remove-all /etc/ldap.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22562'
  tag rid: 'SV-37956r1_rule'
  tag stig_id: 'GEN008120'
  tag gtitle: 'GEN008120'
  tag fix_id: 'F-32445r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
