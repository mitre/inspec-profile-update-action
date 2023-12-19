control 'SV-227972' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf (or equivalent) file must not have an extended ACL.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', 'Verify the permissions of the files.
# ls -lL /var/ldap/ldap_client_file /var/ldap/ldap_client_cred
If the permissions include a "+", the files have an extended ACL, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the files.
# chmod A- /var/ldap/ldap_client_file /var/ldap/ldap_client_cred'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30134r490351_chk'
  tag severity: 'medium'
  tag gid: 'V-227972'
  tag rid: 'SV-227972r603266_rule'
  tag stig_id: 'GEN008120'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30122r490352_fix'
  tag 'documentable'
  tag legacy: ['V-22562', 'SV-40728']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
