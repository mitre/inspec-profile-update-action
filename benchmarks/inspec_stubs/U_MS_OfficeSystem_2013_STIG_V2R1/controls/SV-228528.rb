control 'SV-228528' do
  title 'The Opt-In Wizard must be disabled.'
  desc 'The Opt-in Wizard displays the first time users run a 2013 Microsoft Office application, which allows them to opt into Internet-based services that will help improve their Office experience, such as Microsoft Update, the Customer Experience Improvement Program, Office Diagnostics, and Online Help. If an organization has policies that govern the use of such external resources, allowing users to opt in to these services might cause them to violate the policies.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Privacy >> Trust Center "Disable Opt-in Wizard on first run" is set to "Enabled". 

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\general

If the value 'ShownFirstRunOptin' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Privacy -> Trust Center "Disable Opt-in Wizard on first run" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30761r498862_chk'
  tag severity: 'medium'
  tag gid: 'V-228528'
  tag rid: 'SV-228528r508020_rule'
  tag stig_id: 'DTOO183'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30746r498863_fix'
  tag 'documentable'
  tag legacy: ['V-17664', 'SV-52720']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
