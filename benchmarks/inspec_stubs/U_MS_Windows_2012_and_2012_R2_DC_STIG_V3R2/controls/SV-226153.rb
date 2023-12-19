control 'SV-226153' do
  title 'Device metadata retrieval from the Internet must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting will prevent Windows from retrieving device metadata from the Internet.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Device Metadata\\

Value Name:  PreventDeviceMetadataFromNetwork

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Device Installation >> "Prevent device metadata retrieval from the Internet" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27855r475782_chk'
  tag severity: 'low'
  tag gid: 'V-226153'
  tag rid: 'SV-226153r569184_rule'
  tag stig_id: 'WN12-CC-000022'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27843r475783_fix'
  tag 'documentable'
  tag legacy: ['SV-53185', 'V-21964']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
