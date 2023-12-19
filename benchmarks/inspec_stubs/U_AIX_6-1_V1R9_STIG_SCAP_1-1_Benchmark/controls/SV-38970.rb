control 'SV-38970' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf (or equivalent) file must be owned by root.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'fix', 'Change the owner of the /etc/security/ldap/ldap.cfg file.

# chown root /etc/security/ldap/ldap.cfg'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-22560'
  tag rid: 'SV-38970r1_rule'
  tag stig_id: 'GEN008080'
  tag gtitle: 'GEN008080'
  tag fix_id: 'F-33179r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
