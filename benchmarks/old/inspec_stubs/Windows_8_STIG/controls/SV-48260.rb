control 'SV-48260' do
  title 'The Windows Customer Experience Improvement Program must be disabled.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting ensures the Windows Customer Experience Improvement Program is disabled so information is not passed to the vendor.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\SQMClient\\Windows\\

Value Name: CEIPEnable

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication Settings -> "Turn off Windows Customer Experience Improvement Program" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44938r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16020'
  tag rid: 'SV-48260r2_rule'
  tag stig_id: 'WN08-CC-000045'
  tag gtitle: 'Windows Customer Experience Improvement Program'
  tag fix_id: 'F-41395r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
