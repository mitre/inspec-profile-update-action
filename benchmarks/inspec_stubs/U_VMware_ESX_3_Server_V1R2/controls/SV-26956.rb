control 'SV-26956' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS certificate file must have mode 0644 or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', "Determine the certificate file.
# grep -i '^tls_cacert' /etc/ldap.conf
Check the permissions.
# ls -lL <certpath>
If the mode of the file is more permissive than 0644, this is a finding."
  desc 'fix', 'Change the mode of the file.
# chmod 0644 <certpath>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27903r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22569'
  tag rid: 'SV-26956r1_rule'
  tag stig_id: 'GEN008260'
  tag gtitle: 'GEN008260'
  tag fix_id: 'F-24218r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
