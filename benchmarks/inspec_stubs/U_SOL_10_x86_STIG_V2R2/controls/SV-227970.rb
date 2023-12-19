control 'SV-227970' do
  title 'If the system is using LDAP for authentication or account information, the LDAP configuration file must be owned by root.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', 'Verify the ownership of the files.
# ls -lL /var/ldap/ldap_client_file /var/ldap/ldap_client_cred
If the files are not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the files.
# chown root /var/ldap/ldap_client_file /var/ldap/ldap_client_cred'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30132r490345_chk'
  tag severity: 'medium'
  tag gid: 'V-227970'
  tag rid: 'SV-227970r603266_rule'
  tag stig_id: 'GEN008080'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30120r490346_fix'
  tag 'documentable'
  tag legacy: ['V-22560', 'SV-40727']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
