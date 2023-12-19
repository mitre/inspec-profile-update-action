control 'SV-33452' do
  title 'The Customer Experience Improvement Program for Office must be disabled.'
  desc "When users choose to participate in the Customer Experience Improvement Program (CEIP), Office applications automatically send information to Microsoft about how the applications are used. This information is combined with other CEIP data to help Microsoft solve problems and to improve the products and features customers use most often. This feature does not collect users' names, addresses, or any other identifying information except the IP address that is used to send the data.
By default, users have the opportunity to opt into participation in the CEIP the first time they run an Office application. If your organization has policies that govern the use of external resources such as the CEIP, allowing users to opt in to the program might cause them to violate these policies."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Privacy -> Trust Center “Enable Customer Experience Improvement Program” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common

Criteria: If the value QMEnable is REG_DWORD =0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Privacy -> Trust Center “Enable Customer Experience Improvement Program” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33935r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17612'
  tag rid: 'SV-33452r1_rule'
  tag stig_id: 'DTOO184 - Office System'
  tag gtitle: 'DTOO184 - Cust. Experience Improvement Program'
  tag fix_id: 'F-29624r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
