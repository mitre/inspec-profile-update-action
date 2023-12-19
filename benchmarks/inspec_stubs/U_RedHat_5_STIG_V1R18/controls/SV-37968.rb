control 'SV-37968' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS certificate file must not have an extended ACL.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', "Determine the certificate file.
# grep -i '^tls_cert' /etc/ldap.conf
Check the permissions.
# ls -lL <certpath>
If the mode of the file contains a '+', an extended ACL is present. This is a finding."
  desc 'fix', 'Remove the extended ACL from the certificate file.

Procedure:
For each certificate file found remove all extended permissions.

# setfacl --remove-all <certpath>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37266r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22570'
  tag rid: 'SV-37968r1_rule'
  tag stig_id: 'GEN008280'
  tag gtitle: 'GEN008280'
  tag fix_id: 'F-32502r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
