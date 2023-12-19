control 'SV-228535' do
  title 'The ability to sign into Office365 must be disabled.'
  desc 'Office 2013 can be configured to prompt users for credentials to Office365 using either their Microsoft Account or the user ID assigned by an organization for accessing Office 365.  Access to Office 365 will not be permitted and only locally installed and configured Office installations will be used.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Miscellaneous >> "Block signing into Office" is set to "Enabled: org ID only".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\signin

If the value 'signinoptions' is REG_DWORD = 2, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Miscellaneous -> "Block signing into Office" to "Enabled: org ID only".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30768r498883_chk'
  tag severity: 'medium'
  tag gid: 'V-228535'
  tag rid: 'SV-228535r508020_rule'
  tag stig_id: 'DTOO405'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30753r498884_fix'
  tag 'documentable'
  tag legacy: ['SV-53194', 'V-40862']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
