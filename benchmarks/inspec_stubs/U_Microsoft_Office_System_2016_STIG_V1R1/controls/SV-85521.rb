control 'SV-85521' do
  title 'The Office Telemetry Agent must be configured to obfuscate the file name, file path, and title of Office documents before uploading telemetry data to the shared folder.'
  desc 'This policy setting configures Office Telemetry Agent to disguise, or obfuscate, certain file properties that are reported in telemetry data. If you enable this policy setting, Office Telemetry Agent obfuscates the file name, file path, and title of Office documents before uploading telemetry data to the shared folder. If you disable or do not configure this policy setting, Office Telemetry Agent uploads telemetry data that shows the full file name, file path, and title of all Office documents.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Telemetry Dashboard -> "Turn on privacy setting in Office Telemetry Agent" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\16.0\\osm

Criteria: If the value enablefileobfuscation is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Telemetry Dashboard -> "Turn on privacy setting in Office Telemetry Agent" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-71341r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70897'
  tag rid: 'SV-85521r1_rule'
  tag stig_id: 'DTOO416'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-77229r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
