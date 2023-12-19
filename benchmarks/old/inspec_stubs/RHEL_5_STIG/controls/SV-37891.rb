control 'SV-37891' do
  title 'Samba must be configured to use an authentication mechanism other than "share."'
  desc 'Samba share authentication does not provide for individual user identification and must not be used.'
  desc 'fix', 'Edit the "/etc/samba/smb.conf" file and change the "security" setting to "user" or another valid setting other than "share".'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22499'
  tag rid: 'SV-37891r1_rule'
  tag stig_id: 'GEN006225'
  tag gtitle: 'GEN006225'
  tag fix_id: 'F-32385r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
