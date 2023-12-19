control 'SV-33472' do
  title 'The Internet Fax Feature must be disabled.'
  desc 'Excel, PowerPoint, and Word users can use the Internet Fax feature to send documents to fax recipients through an Internet fax service provider. If your organization has policies that govern the time, place, or manner in which faxes are sent, this feature could help users evade those policies.
By default, Office users can use the Internet Fax feature.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Services -> Fax “Disable Internet Fax feature” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\services\\fax

Criteria: If the value NoFax is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Services -> Fax “Disable Internet Fax feature” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33955r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17661'
  tag rid: 'SV-33472r1_rule'
  tag stig_id: 'DTOO198 - Office System'
  tag gtitle: 'DTOO198 - Internet Fax Feature'
  tag fix_id: 'F-29644r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
