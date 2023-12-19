control 'SV-218650' do
  title 'Samba must be configured to not allow guest access to shares.'
  desc 'Guest access to shares permits anonymous access and is not permitted.'
  desc 'check', "Check the access to shares for Samba.
# grep -i 'guest ok' /etc/samba/smb.conf 
If the setting exists and is set to 'yes', this is a finding."
  desc 'fix', 'Edit the "/etc/samba/smb.conf" file and change the "guest ok" setting to "no".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20125r556148_chk'
  tag severity: 'medium'
  tag gid: 'V-218650'
  tag rid: 'SV-218650r603259_rule'
  tag stig_id: 'GEN006235'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20123r556149_fix'
  tag 'documentable'
  tag legacy: ['V-22501', 'SV-64013']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
