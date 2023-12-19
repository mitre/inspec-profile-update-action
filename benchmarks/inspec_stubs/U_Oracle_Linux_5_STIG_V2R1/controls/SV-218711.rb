control 'SV-218711' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS key file must not have an extended ACL.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', "Determine the key file.
# grep -i '^tls_key' /etc/ldap.conf
Check the permissions.
# ls -lL <keypath>
If the permissions of the file contains a '+', an extended ACL is present. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the key file.

Procedure:
For each key file found remove all extended permissions.

# setfacl --remove-all <keypath>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20186r556550_chk'
  tag severity: 'medium'
  tag gid: 'V-218711'
  tag rid: 'SV-218711r603259_rule'
  tag stig_id: 'GEN008360'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20184r556551_fix'
  tag 'documentable'
  tag legacy: ['V-22574', 'SV-63213']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
