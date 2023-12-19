control 'SV-218696' do
  title 'If the system is using LDAP for authentication or account information the /etc/ldap.conf (or equivalent) file must have mode 0644 or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', 'Check the permissions of the file.
# ls -lL /etc/ldap.conf
If the mode of the file is more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the permissions of the file.
# chmod 0644 /etc/ldap.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20171r556505_chk'
  tag severity: 'medium'
  tag gid: 'V-218696'
  tag rid: 'SV-218696r603259_rule'
  tag stig_id: 'GEN008060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20169r556506_fix'
  tag 'documentable'
  tag legacy: ['V-22559', 'SV-63349']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
