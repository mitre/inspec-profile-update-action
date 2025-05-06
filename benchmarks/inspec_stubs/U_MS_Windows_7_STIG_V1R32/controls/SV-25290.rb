control 'SV-25290' do
  title 'Device metadata retrieval from the Internet must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  This setting will prevent Windows from retrieving device metadata from the Internet.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Device Metadata\\

Value Name:  PreventDeviceMetadataFromNetwork

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Device Installation >> "Prevent device metadata retrieval from the Internet" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62015r1_chk'
  tag severity: 'low'
  tag gid: 'V-21964'
  tag rid: 'SV-25290r2_rule'
  tag gtitle: 'Prevent device metadata retrieval from Internet'
  tag fix_id: 'F-66911r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
