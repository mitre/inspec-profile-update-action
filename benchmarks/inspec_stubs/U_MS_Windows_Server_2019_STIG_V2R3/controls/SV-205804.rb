control 'SV-205804' do
  title 'Windows Server 2019 Autoplay must be turned off for non-volume devices.'
  desc 'Allowing AutoPlay to execute may introduce malicious code to a system. AutoPlay begins reading from a drive as soon as media is inserted into the drive. As a result, the setup file of programs or music on audio media may start. This setting will disable AutoPlay for non-volume devices, such as Media Transfer Protocol (MTP) devices.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoAutoplayfornonVolume

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> "Disallow Autoplay for non-volume devices" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Windows Server 2019'
  tag check_id: 'C-6069r355774_chk'
  tag severity: 'high'
  tag gid: 'V-205804'
  tag rid: 'SV-205804r569188_rule'
  tag stig_id: 'WN19-CC-000210'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-6069r355775_fix'
  tag 'documentable'
  tag legacy: ['V-93373', 'SV-103459']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
