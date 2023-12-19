control 'SV-48340' do
  title 'Basic authentication for RSS feeds over HTTP must be turned off.'
  desc 'Basic authentication uses plain text passwords that could be used to compromise a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

Value Name: AllowBasicAuthInClear

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds -> "Turn on Basic feed authentication over HTTP" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45011r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36709'
  tag rid: 'SV-48340r2_rule'
  tag stig_id: 'WN08-CC-000106'
  tag gtitle: 'WINCC-000106'
  tag fix_id: 'F-41472r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
