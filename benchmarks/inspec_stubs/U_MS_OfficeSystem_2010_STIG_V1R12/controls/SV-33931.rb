control 'SV-33931' do
  title 'The Opt-In Wizard must be disabled.'
  desc 'The Opt-in Wizard displays the first time users run a 2010 Microsoft Office application, which allows them to opt into Internet–based services that will help improve their Office experience, such as Microsoft Update, the Customer Experience Improvement Program, Office Diagnostics, and Online Help. If your organization has policies that govern the use of such external resources, allowing users to opt in to these services might cause them to violate the policies.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Privacy -> Trust Center “Disable Opt-in Wizard on first run” must be set to “Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\general

Criteria: If the value ShownFirstRunOptin is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Privacy -> Trust Center “Disable Opt-in Wizard on first run” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-34373r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17664'
  tag rid: 'SV-33931r1_rule'
  tag stig_id: 'DTOO183 - Office System'
  tag gtitle: 'DTOO183 - Opt-In Wizard on first run use'
  tag fix_id: 'F-30009r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
