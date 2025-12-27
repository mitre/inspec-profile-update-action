control 'SV-33454' do
  title 'Automation Security to enforce macro level security in Office documents must be configured.'
  desc 'When a separate program is used to launch Microsoft Office Excel, PowerPoint, or Word programmatically, any macros can run in the programmatically opened application without being blocked. This functionality could allow an attacker to use automation to run malicious code in Excel, PowerPoint, or Word.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010-> Security Settings “Automation Security” must be "Enabled (Use application macro security level)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\Common\\Security

Criteria: If the value AutomationSecurity is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010-> Security Settings “Automation Security” to “Enabled (Use application macro security level)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33937r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17741'
  tag rid: 'SV-33454r1_rule'
  tag stig_id: 'DTOO193 - Office System'
  tag gtitle: 'DTOO193 - Automation Security'
  tag fix_id: 'F-29626r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
