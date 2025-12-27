control 'SV-228542' do
  title 'The  Office Telemetry Agent and Office applications must be configured to collect telemetry data.'
  desc 'Office Telemetry is a new compatibility monitoring framework. When an Office document or solution is loaded, used, closed, or raises an error in certain Office 2013 applications, the Office Telemetry application adds a record about the event to a local data store. Each record includes a description of the problem and a link to more information. Inventory and usage data is also tracked. This policy setting allows the data collection features in Office that are used by the Office Telemetry Dashboard and Office Telemetry Log to be turned on. If this policy setting is enabled, Office Telemetry Agent and Office applications will collect telemetry data, which includes Office application usage, most recently used Office documents (including file names) and solutions usage, compatibility issues, and critical errors that occur on the local computers. Office Telemetry Dashboard can be used to view this data remotely, and users can use Office Telemetry Log to view this data on their local computers. If this policy setting is disabled or not configured, the Office Telemetry Agent and Office applications do not generate or collect telemetry data.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Telemetry Dashboard >> "Turn on telemetry data collection" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\osm

If the value 'enablelogging' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Telemetry Dashboard >> "Turn on telemetry data collection" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30775r498904_chk'
  tag severity: 'medium'
  tag gid: 'V-228542'
  tag rid: 'SV-228542r508020_rule'
  tag stig_id: 'DTOO417'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30760r498905_fix'
  tag 'documentable'
  tag legacy: ['SV-53219', 'V-40887']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
