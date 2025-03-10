control 'SV-213448' do
  title 'Windows Defender AV must be configured to scan archive files.'
  desc 'This policy setting allows you to configure scans for malicious software and unwanted software in archive files such as .ZIP or .CAB files. If you enable or do not configure this setting archive files will be scanned. If you disable this setting archive files will not be scanned.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Scan -> "Scan archive files" is set to "Enabled" or "Not Configured".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Scan

Criteria: If the value "DisableArchiveScanning" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Scan -> "Scan archive files" to "Enabled " or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14673r314653_chk'
  tag severity: 'medium'
  tag gid: 'V-213448'
  tag rid: 'SV-213448r569189_rule'
  tag stig_id: 'WNDF-AV-000024'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-14671r314654_fix'
  tag 'documentable'
  tag legacy: ['SV-89913', 'V-75233']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
