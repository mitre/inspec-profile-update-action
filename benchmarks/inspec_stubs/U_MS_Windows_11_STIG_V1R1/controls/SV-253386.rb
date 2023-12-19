control 'SV-253386' do
  title 'Autoplay must be turned off for non-volume devices.'
  desc 'Allowing autoplay to execute may introduce malicious code to a system. Autoplay begins reading from a drive as soon as media is inserted in the drive. As a result, the setup file of programs or music on audio media may start. This setting will disable autoplay for non-volume devices (such as Media Transfer Protocol (MTP) devices).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoAutoplayfornonVolume

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> "Disallow Autoplay for non-volume devices" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56839r829240_chk'
  tag severity: 'high'
  tag gid: 'V-253386'
  tag rid: 'SV-253386r829242_rule'
  tag stig_id: 'WN11-CC-000180'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-56789r829241_fix'
  tag 'documentable'
  tag cci: ['CCI-001734']
  tag nist: ['CM-10 (1)']
end
