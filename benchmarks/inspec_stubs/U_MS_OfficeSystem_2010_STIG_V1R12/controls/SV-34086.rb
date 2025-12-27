control 'SV-34086' do
  title 'Online content options must be configured for offline content availability.'
  desc "The Office 2010 Help system automatically searches Microsoft Office.com for content when a computer is connected to the Internet.  Users can change this default by clearing the Search Microsoft Office.com for Help content when I'm connected to the Internet check box in the Privacy Options section of the Trust Center.  If your organization has policies that govern the use of external resources such as Office.com, allowing the Help system to download content might cause users to violate these policies."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Tools | Options | General | Service Options... -> Online Content  “Online content options” must be set to “Enabled: Search only offline content whenever available”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\internet

Criteria: If the value UseOnlineContent is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Tools | Options | General | Service Options... -> Online Content  “Online content options” to “Enabled: Search only offline content whenever available”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-34226r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26630'
  tag rid: 'SV-34086r1_rule'
  tag stig_id: 'DTOO345 - Office System'
  tag gtitle: 'DTOO345 - Online content options'
  tag fix_id: 'F-29916r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
