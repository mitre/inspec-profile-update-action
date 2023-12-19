control 'SV-25299' do
  title 'Turn off autoplay for non-volume devices.'
  desc 'This setting will disable autoplay for non-volume devices (such as Media Transfer Protocol (MTP) devices).'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name:  NoAutoplayfornonVolume

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> “Turn off Autoplay for non-volume devices” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-26859r1_chk'
  tag severity: 'medium'
  tag gid: 'V-21973'
  tag rid: 'SV-25299r1_rule'
  tag gtitle: 'Autoplay for non-volume devices'
  tag fix_id: 'F-22962r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
