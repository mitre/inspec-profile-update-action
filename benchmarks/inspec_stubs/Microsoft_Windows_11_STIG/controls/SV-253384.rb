control 'SV-253384' do
  title 'The setting to allow Microsoft accounts to be optional for modern style apps must be enabled.'
  desc 'Control of credentials and the system must be maintained within the enterprise. Enabling this setting allows enterprise credentials to be used with modern style apps that support this, instead of Microsoft accounts.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: MSAOptional

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> App Runtime >> "Allow Microsoft accounts to be optional" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56837r829234_chk'
  tag severity: 'low'
  tag gid: 'V-253384'
  tag rid: 'SV-253384r829236_rule'
  tag stig_id: 'WN11-CC-000170'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56787r829235_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
