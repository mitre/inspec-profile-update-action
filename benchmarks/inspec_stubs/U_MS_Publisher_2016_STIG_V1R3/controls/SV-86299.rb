control 'SV-86299' do
  title 'The Publisher Automation Security Level must be configured for high security.'
  desc 'This policy setting controls whether macros opened programmatically by another application can run in Publisher.If you enable this policy setting, you may choose an option for controlling macro behavior in Publisher when the application is opened programmatically:- Low (enabled): Macros can run in the programmatically opened application.- By UI (prompted): Macro functionality is determined by the setting in the "Macro Settings" section of the Trust Center.- High (disabled):  All macros are disabled in the programmatically opened application.If you disable or do not configure this policy setting, Publisher will use the default Macro setting in Trust Center.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Publisher 2016 -> Security "Publisher Automation Security Level" is set to "Enabled and High (Disabled)" is selected. 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\Common\\Security 

Criteria: If the value AutomationSecurityPublisher is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Publisher 2016 -> Security "Publisher Automation Security Level" to "Enabled and High (Disabled)" is selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Publisher 2016'
  tag check_id: 'C-71981r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71675'
  tag rid: 'SV-86299r1_rule'
  tag stig_id: 'DTOO323'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-77999r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
