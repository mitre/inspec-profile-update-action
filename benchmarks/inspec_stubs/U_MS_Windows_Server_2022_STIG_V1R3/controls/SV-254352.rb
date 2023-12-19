control 'SV-254352' do
  title 'Windows Server 2022 Autoplay must be turned off for nonvolume devices.'
  desc 'Allowing AutoPlay to execute may introduce malicious code to a system. AutoPlay begins reading from a drive as soon as media is inserted into the drive. As a result, the setup file of programs or music on audio media may start. This setting will disable AutoPlay for nonvolume devices, such as Media Transfer Protocol (MTP) devices.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoAutoplayfornonVolume

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> Disallow Autoplay for nonvolume devices to "Enabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57837r848870_chk'
  tag severity: 'high'
  tag gid: 'V-254352'
  tag rid: 'SV-254352r848872_rule'
  tag stig_id: 'WN22-CC-000210'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-57788r848871_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
