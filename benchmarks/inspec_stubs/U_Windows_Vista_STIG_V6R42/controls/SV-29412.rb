control 'SV-29412' do
  title 'File and Folder Publish to Web option unavailable.'
  desc 'This check verifies that the system is configured to make the options to publish to the web unavailable from File and Folder Tasks in Windows folders.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer 

Value Name:  NoPublishingWizard

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication setting ‘Turn off the "Publish to Web" task for files and folders’ to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-11601r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14255'
  tag rid: 'SV-29412r1_rule'
  tag gtitle: 'Publish to Web'
  tag fix_id: 'F-13580r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
