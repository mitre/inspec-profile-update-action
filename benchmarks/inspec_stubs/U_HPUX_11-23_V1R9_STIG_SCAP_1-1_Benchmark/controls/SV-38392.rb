control 'SV-38392' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS certificate file must have mode 0644 or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'fix', 'Change the permissions of the LDAP client certificate file.
# chmod 0644 <cert file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22569'
  tag rid: 'SV-38392r1_rule'
  tag stig_id: 'GEN008260'
  tag gtitle: 'GEN008260'
  tag fix_id: 'F-32159r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
