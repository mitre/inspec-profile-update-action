control 'SV-37951' do
  title 'If the system is using LDAP for authentication or account information the /etc/ldap.conf (or equivalent) file must have mode 0644 or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'fix', 'Change the permissions of the file.
# chmod 0644 /etc/ldap.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22559'
  tag rid: 'SV-37951r1_rule'
  tag stig_id: 'GEN008060'
  tag gtitle: 'GEN008060'
  tag fix_id: 'F-32441r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
