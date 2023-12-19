control 'SV-218697' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf (or equivalent) file must be owned by root.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', 'Check the ownership of the file.
# ls -lL /etc/ldap.conf
If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the file.

# chown root /etc/ldap.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20172r556508_chk'
  tag severity: 'medium'
  tag gid: 'V-218697'
  tag rid: 'SV-218697r603259_rule'
  tag stig_id: 'GEN008080'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20170r556509_fix'
  tag 'documentable'
  tag legacy: ['V-22560', 'SV-63321']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
