control 'SV-228541' do
  title 'The ability of the Office Telemetry Agent to periodically upload telemetry data to a shared folder must be disabled.'
  desc 'Office Telemetry is a new compatibility monitoring framework. When an Office document or solution is loaded, used, closed, or raises an error in certain Office 2013 applications, the Office Telemetry application adds a record about the event to a local data store. Each record includes a description of the problem and a link to more information. Inventory and usage data is also tracked. The actual logging capability will be enabled, but this policy allows that data to be uploaded to a remote location which, if enabled, could pass information about the internal network and configuration to that remote site.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Telemetry Dashboard >> "Turn on data uploading for Office Telemetry Agent" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\osm

If the value 'enableupload' is REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Telemetry Dashboard >> "Turn on data uploading for Office Telemetry Agent" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30774r498901_chk'
  tag severity: 'medium'
  tag gid: 'V-228541'
  tag rid: 'SV-228541r508020_rule'
  tag stig_id: 'DTOO415'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30759r498902_fix'
  tag 'documentable'
  tag legacy: ['V-40885', 'SV-53217']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
