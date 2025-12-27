control 'SV-218648' do
  title 'Samba must be configured to use an authentication mechanism other than share.'
  desc 'Samba share authentication does not provide for individual user identification and must not be used.'
  desc 'check', 'Check the security mode of the Samba configuration.
# grep -i security /etc/samba/smb.conf 
If the security mode is "share", this is a finding.'
  desc 'fix', 'Edit the "/etc/samba/smb.conf" file and change the "security" setting to "user" or another valid setting other than "share".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20123r556142_chk'
  tag severity: 'medium'
  tag gid: 'V-218648'
  tag rid: 'SV-218648r603259_rule'
  tag stig_id: 'GEN006225'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20121r556143_fix'
  tag 'documentable'
  tag legacy: ['V-22499', 'SV-64049']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
