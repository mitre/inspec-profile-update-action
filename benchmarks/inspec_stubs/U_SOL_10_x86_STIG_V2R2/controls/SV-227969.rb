control 'SV-227969' do
  title 'If the system is using LDAP for authentication or account information the LDAP client configuration file must have mode 0600 or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', 'Verify the permissions of the files.
# ls -lL /var/ldap/ldap_client_file /var/ldap/ldap_client_cred
If the mode of either file is more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the permissions of the files.
# chmod 0600 /var/ldap/ldap_client_file /var/ldap/ldap_client_cred'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30131r490342_chk'
  tag severity: 'medium'
  tag gid: 'V-227969'
  tag rid: 'SV-227969r603266_rule'
  tag stig_id: 'GEN008060'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30119r490343_fix'
  tag 'documentable'
  tag legacy: ['V-22559', 'SV-40726']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
