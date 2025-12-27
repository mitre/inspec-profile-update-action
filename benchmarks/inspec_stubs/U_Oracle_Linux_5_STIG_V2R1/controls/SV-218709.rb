control 'SV-218709' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS key file must be group-owned by root, bin, or sys.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', "Determine the key file.

# grep -i '^tls_key' /etc/ldap.conf

Check the group ownership.
# ls -lL <keypath>

If the file is not group owned by root, bin, or sys, this is a finding."
  desc 'fix', 'Change the group ownership of the file.

# chgrp root <keypath>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20184r556544_chk'
  tag severity: 'medium'
  tag gid: 'V-218709'
  tag rid: 'SV-218709r603259_rule'
  tag stig_id: 'GEN008320'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20182r556545_fix'
  tag 'documentable'
  tag legacy: ['V-22572', 'SV-63235']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
