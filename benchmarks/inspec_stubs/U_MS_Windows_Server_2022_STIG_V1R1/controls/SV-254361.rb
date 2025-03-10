control 'SV-254361' do
  title 'Windows Server 2022 Microsoft Defender antivirus SmartScreen must be enabled.'
  desc 'Microsoft Defender antivirus SmartScreen helps protect systems from programs downloaded from the internet that may be malicious. Enabling SmartScreen can block potentially malicious programs or warn users.'
  desc 'check', 'This is applicable to unclassified systems; for other systems, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

Value Name: EnableSmartScreen

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> File Explorer >> Configure Windows Defender SmartScreen to "Enabled" with either option "Warn" or "Warn and prevent bypass" selected.

Windows Server 2022 includes duplicate policies for this setting. It can also be configured under Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender SmartScreen >> Explorer.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57846r848897_chk'
  tag severity: 'medium'
  tag gid: 'V-254361'
  tag rid: 'SV-254361r848899_rule'
  tag stig_id: 'WN22-CC-000300'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-57797r848898_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
