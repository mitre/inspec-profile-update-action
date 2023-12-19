control 'SV-48251' do
  title 'Microsoft Active Protection Service membership must be disabled.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting disables Microsoft Active Protection Service membership and reporting.'
  desc 'check', 'If the following registry value exists and is set to "1" (Basic) or "2" (Advanced), this is a finding.
If the following registry value does not exist, this is not a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\\

Value Name:  SpyNetReporting

Type:  REG_DWORD
Value:  1 or 2 = a Finding'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender >> MAPS >> "Join Microsoft MAPS" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-57987r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15713'
  tag rid: 'SV-48251r4_rule'
  tag stig_id: 'WN08-CC-000111'
  tag gtitle: 'Defender – SpyNet Reporting'
  tag fix_id: 'F-71645r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
