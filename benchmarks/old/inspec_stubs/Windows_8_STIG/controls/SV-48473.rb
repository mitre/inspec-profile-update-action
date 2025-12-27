control 'SV-48473' do
  title 'Autoplay must be turned off for non-volume devices.'
  desc 'Allowing autoplay to execute may introduce malicious code to a system.  Autoplay begins reading from a drive as soon as you insert media in the drive.  As a result, the setup file of programs or music on audio media may start.  This setting will disable autoplay for non-volume devices (such as Media Transfer Protocol (MTP) devices).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoAutoplayfornonVolume

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> "Disallow Autoplay for non-volume devices" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45137r2_chk'
  tag severity: 'high'
  tag gid: 'V-21973'
  tag rid: 'SV-48473r2_rule'
  tag stig_id: 'WN08-CC-000072'
  tag gtitle: 'Autoplay for non-volume devices'
  tag fix_id: 'F-41600r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
