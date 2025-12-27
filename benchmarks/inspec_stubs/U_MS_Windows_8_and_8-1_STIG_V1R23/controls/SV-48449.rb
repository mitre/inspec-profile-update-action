control 'SV-48449' do
  title 'Device metadata retrieval from the Internet must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting will prevent Windows from retrieving device metadata from the Internet.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Device Metadata\\

Value Name:  PreventDeviceMetadataFromNetwork

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Device Installation >> "Prevent device metadata retrieval from the Internet" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45112r3_chk'
  tag severity: 'low'
  tag gid: 'V-21964'
  tag rid: 'SV-48449r3_rule'
  tag stig_id: 'WN08-CC-000022'
  tag gtitle: 'Prevent device metadata retrieval from Internet'
  tag fix_id: 'F-41577r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
