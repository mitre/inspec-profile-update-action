control 'SV-55994' do
  title 'The setting to allow Microsoft accounts to be optional for modern style apps must be enabled.'
  desc 'Control of credentials and the system must be maintained within the enterprise.  Enabling this setting allows enterprise credentials to be used with modern style apps that support this, instead of Microsoft accounts.'
  desc 'check', 'Verify the registry value below. If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System

Value Name: MSAOptional

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> App Runtime >> "Allow Microsoft accounts to be optional" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-66269r1_chk'
  tag severity: 'low'
  tag gid: 'V-43241'
  tag rid: 'SV-55994r3_rule'
  tag stig_id: 'WN08-CC-000141'
  tag gtitle: 'WINCC-000141'
  tag fix_id: 'F-71657r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
