control 'SV-213449' do
  title 'Microsoft Defender AV must be configured to scan removable drives.'
  desc 'This policy setting allows the management of whether or not to scan for malicious software and unwanted software in the contents of removable drives such as USB flash drives when running a full scan. If this setting is enabled, removable drives will be scanned during any type of scan. If this setting is disabled or not configured, removable drives will not be scanned during a full scan. Removable drives may still be scanned during quick scan and custom scan.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Scan >> "Scan removable drives" is set to "Enabled".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Scan

Criteria: If the value "DisableRemovableDriveScanning" is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender Antivirus >> Scan >> "Scan removable drives" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14674r820194_chk'
  tag severity: 'medium'
  tag gid: 'V-213449'
  tag rid: 'SV-213449r823068_rule'
  tag stig_id: 'WNDF-AV-000025'
  tag gtitle: 'SRG-APP-000073'
  tag fix_id: 'F-14672r820195_fix'
  tag 'documentable'
  tag legacy: ['SV-89915', 'V-75235']
  tag cci: ['CCI-000870']
  tag nist: ['MA-3 (2)']
end
