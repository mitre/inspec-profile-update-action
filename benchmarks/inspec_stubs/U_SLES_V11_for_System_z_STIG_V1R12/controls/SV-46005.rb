control 'SV-46005' do
  title 'If the system is using LDAP for authentication or account information the /etc/ldap.conf (or equivalent) file must have mode 0644 or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', 'Check the permissions of the file.
# ls -lL /etc/ldap.conf
If the mode of the file is more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the permissions of the file.
# chmod 0644 /etc/ldap.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43288r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22559'
  tag rid: 'SV-46005r1_rule'
  tag stig_id: 'GEN008060'
  tag gtitle: 'GEN008060'
  tag fix_id: 'F-39371r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
