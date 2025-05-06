control 'SV-34082' do
  title 'Hyperlinks to web templates in File | New and task panes must be disabled.'
  desc 'This setting controls whether users can follow hyperlinks to templates on Office.com from within Office 2010 applications.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Miscellaneous “Disable hyperlinks to web templates in File | New and task panes” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\internet

Criteria: If the value DisableTemplatesOnTheWeb is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Miscellaneous “Disable hyperlinks to web templates in File | New and task panes” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-34221r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26626'
  tag rid: 'SV-34082r1_rule'
  tag stig_id: 'DTOO306 - Office System'
  tag gtitle: 'DTOO306 - Disable hyperlinks to web templates'
  tag fix_id: 'F-29912r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
