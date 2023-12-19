control 'SV-46042' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS key file must not have an extended ACL.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', "Determine the key file.
# grep -i '^tls_key' /etc/ldap.conf
Check the permissions.
# ls -lL <keypath>
If the mode the file contains a '+', an extended ACL is present. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the key file.

Procedure:
For each key file found remove all extended permissions.

# setfacl --remove-all <keypath>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43313r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22574'
  tag rid: 'SV-46042r1_rule'
  tag stig_id: 'GEN008360'
  tag gtitle: 'GEN008360'
  tag fix_id: 'F-39402r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
