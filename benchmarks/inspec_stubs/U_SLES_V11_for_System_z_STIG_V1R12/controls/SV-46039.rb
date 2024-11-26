control 'SV-46039' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS key file must be group-owned by root, bin, or sys.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', "Determine the key file.
# grep -i '^tls_key' /etc/ldap.conf
Check the group ownership.
# ls -lL <keypath>
If the group wner of the file is not root, this is a finding."
  desc 'fix', 'Change the group ownership of the file.
# chgrp root <keypath>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43311r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22572'
  tag rid: 'SV-46039r1_rule'
  tag stig_id: 'GEN008320'
  tag gtitle: 'GEN008320'
  tag fix_id: 'F-39400r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
