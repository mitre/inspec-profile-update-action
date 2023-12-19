control 'SV-218707' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20182r556538_chk'
  tag severity: 'medium'
  tag gid: 'V-218707'
  tag rid: 'SV-218707r603259_rule'
  tag stig_id: 'GEN008280'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20180r556539_fix'
  tag 'documentable'
  tag legacy: ['V-22570', 'SV-63245']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
