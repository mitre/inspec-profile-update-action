control 'SV-33461' do
  title 'Microsoft passport Service for content must be disallowed.'
  desc 'This controls whether users can open protected content created with a Windows Live ID (formerly Microsoft .NET Passport) authenticated account.   If your organization has policies that govern access to external services such as Windows Live ID, this capability could allow users to violate those policies.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Manage Restricted Permissions “Disable Microsoft Passport service for content with restricted permission” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\drm

Criteria: If the value DisablePassportCertification is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Manage Restricted Permissions “Disable Microsoft Passport service for content with restricted permission” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33944r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17662'
  tag rid: 'SV-33461r1_rule'
  tag stig_id: 'DTOO202 - Office System'
  tag gtitle: 'DTOO202 - Microsoft Passport Service'
  tag fix_id: 'F-29633r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
