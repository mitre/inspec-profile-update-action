control 'SV-33517' do
  title 'Upload method for publishing calendars to Office Online must be restricted.'
  desc 'When users publish their calendar to Microsoft Office Online using the Microsoft Office Outlook Calendar Sharing Service, Outlook updates the calendars online at regular intervals unless they click Advanced and select Single Upload: Updates will not be uploaded from the Published Calendar Settings dialog box. If your organization has policies that govern the use of external resources such as Microsoft Office Online, allowing Outlook to publish calendar updates automatically might violate those policies.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service “Restrict upload method” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\pubcal

Criteria: If the value SingleUploadOnly is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service “Restrict upload method” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34004r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17777'
  tag rid: 'SV-33517r1_rule'
  tag stig_id: 'DTOO220 - Outlook'
  tag gtitle: 'DTOO220 - Upload methods'
  tag fix_id: 'F-29692r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
