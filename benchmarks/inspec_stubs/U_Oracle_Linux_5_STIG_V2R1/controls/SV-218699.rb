control 'SV-218699' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf (or equivalent) file must not have an extended ACL.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', "Check the permissions of the file.
# ls -lL /etc/ldap.conf
If the mode includes a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the "/etc/ldap.conf" file.
# setfacl --remove-all /etc/ldap.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20174r556514_chk'
  tag severity: 'medium'
  tag gid: 'V-218699'
  tag rid: 'SV-218699r603259_rule'
  tag stig_id: 'GEN008120'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20172r556515_fix'
  tag 'documentable'
  tag legacy: ['V-22562', 'SV-63315']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
