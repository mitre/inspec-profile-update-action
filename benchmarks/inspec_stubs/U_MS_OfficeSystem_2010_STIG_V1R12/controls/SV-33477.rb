control 'SV-33477' do
  title 'Upload of document templates to Office Online must be prevented.'
  desc 'Office users can share Excel, PowerPoint, and Word templates they create with other Microsoft Office users around the world by uploading them to the community area of the Microsoft Office Online Web site. If your organization has policies that govern the use of external resources such as Office Online, allowing users to upload templates might enable them to violate those policies.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Tools \\ Options \\ General \\ Web Options... “Prevent users from uploading document templates to the Office.com Community” must  be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\internet

Criteria: If the value DisableCustomerSubmittedUpload is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Tools \\ Options \\ General \\ Web Options... “Prevent users from uploading document templates to the Office.com Community” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33960r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17767'
  tag rid: 'SV-33477r1_rule'
  tag stig_id: 'DTOO178 - Office System'
  tag gtitle: 'DTOO178 - Uploads to Office Online'
  tag fix_id: 'F-29649r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
