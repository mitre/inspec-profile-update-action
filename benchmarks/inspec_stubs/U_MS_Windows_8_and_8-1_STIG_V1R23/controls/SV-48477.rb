control 'SV-48477' do
  title 'Downloading of game update information must be turned off.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting will prevent the system from downloading game update information from Windows Metadata Services.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\GameUX\\

Value Name: GameUpdateOptions

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Game Explorer -> "Turn off game updates" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45139r2_chk'
  tag severity: 'low'
  tag gid: 'V-21974'
  tag rid: 'SV-48477r2_rule'
  tag stig_id: 'WN08-CC-000093'
  tag gtitle: 'Turn Off Game Updates'
  tag fix_id: 'F-41602r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
