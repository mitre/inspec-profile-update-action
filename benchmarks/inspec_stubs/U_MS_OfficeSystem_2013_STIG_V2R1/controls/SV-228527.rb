control 'SV-228527' do
  title 'The Office Telemetry Agent must be configured to obfuscate the file name, file path, and title of Office documents before uploading telemetry data to the shared folder.'
  desc 'This policy setting configures the Office Telemetry Agent to disguise, or obfuscate, certain file properties that are reported in telemetry data. If this policy setting is enabled, Office Telemetry Agent obfuscates the file name, file path, and title of Office documents before uploading telemetry data to the shared folder. If this policy setting is disabled or not configured, the Office Telemetry Agent uploads telemetry data that shows the full file name, file path, and title of all Office documents.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Telemetry Dashboard >> "Turn on privacy setting in Office Telemetry Agent" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\osm

If the value 'enablefileobfuscation' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Telemetry Dashboard >> "Turn on privacy setting in Office Telemetry Agent" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30760r498859_chk'
  tag severity: 'medium'
  tag gid: 'V-228527'
  tag rid: 'SV-228527r508020_rule'
  tag stig_id: 'DTOO416'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30745r498860_fix'
  tag 'documentable'
  tag legacy: ['SV-53218', 'V-40886']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
