control 'SV-16661' do
  title 'Media DRM – Internet Access'
  desc 'This check verifies that Windows Media Digital Rights Management will be prevented from accessing the internet.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\WMDRM\\

Value Name:  DisableOnline

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Digital Rights Management “Prevent Windows Media DRM Internet Access” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-15410r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15722'
  tag rid: 'SV-16661r1_rule'
  tag gtitle: 'Media DRM – Internet Access'
  tag fix_id: 'F-15614r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
