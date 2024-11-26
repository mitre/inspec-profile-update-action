control 'SV-228545' do
  title 'Automation Security to enforce macro level security in Office documents must be configured.'
  desc 'When a separate program is used to launch Microsoft Office Excel, PowerPoint, or Word programmatically, any macros can run in the programmatically opened application without being blocked. This functionality could allow an attacker to use automation to run malicious code in Excel, PowerPoint, or Word.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Security Settings "Automation Security" is set to "Enabled (Use application macro security level)".

Use the Windows Registry Editor to navigate to the following HKCU\\Software\\Policies\\Microsoft\\Office\\Common\\Security

If the value "AutomationSecurity" is REG_DWORD =2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Security Settings "Automation Security" to "Enabled (Use application macro security level)".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30778r557513_chk'
  tag severity: 'medium'
  tag gid: 'V-228545'
  tag rid: 'SV-228545r557514_rule'
  tag stig_id: 'DTOO193'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-30763r498914_fix'
  tag 'documentable'
  tag legacy: ['SV-52730', 'V-17741']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
