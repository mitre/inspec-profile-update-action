control 'SV-205688' do
  title 'Windows Server 2019 downloading print driver packages over HTTP must be turned off.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and will prevent uncontrolled updates to the system. 

This setting prevents the computer from downloading print driver packages over HTTP.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\

Value Name: DisableWebPnPDownload

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Internet Communication Management >> Internet Communication settings >> "Turn off downloading of print drivers over HTTP" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-5953r354982_chk'
  tag severity: 'medium'
  tag gid: 'V-205688'
  tag rid: 'SV-205688r569188_rule'
  tag stig_id: 'WN19-CC-000150'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-5953r354983_fix'
  tag 'documentable'
  tag legacy: ['SV-103489', 'V-93403']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
