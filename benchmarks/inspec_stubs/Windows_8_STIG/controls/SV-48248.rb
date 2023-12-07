control 'SV-48248' do
  title 'Game explorer information must not be downloaded from Windows Metadata Services.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents game information from being downloaded from Windows Metadata Services.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\GameUX\\

Value Name: DownloadGameInfo

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Game Explorer -> "Turn off downloading of game information" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44926r1_chk'
  tag severity: 'low'
  tag gid: 'V-15709'
  tag rid: 'SV-48248r2_rule'
  tag stig_id: 'WN08-CC-000092'
  tag gtitle: 'Game Explorer Information Downloads'
  tag fix_id: 'F-41383r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
