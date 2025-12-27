control 'SV-227060' do
  title 'If the system is using LDAP for authentication or account information the LDAP client configuration file must have mode 0600 or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', 'Verify the permissions of the files.
# ls -lL /var/ldap/ldap_client_file /var/ldap/ldap_client_cred
If the mode of either file is more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the permissions of the files.
# chmod 0600 /var/ldap/ldap_client_file /var/ldap/ldap_client_cred'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29222r485555_chk'
  tag severity: 'medium'
  tag gid: 'V-227060'
  tag rid: 'SV-227060r603265_rule'
  tag stig_id: 'GEN008060'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29210r485556_fix'
  tag 'documentable'
  tag legacy: ['SV-40726', 'V-22559']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
