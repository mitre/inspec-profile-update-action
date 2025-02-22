control 'SV-33523' do
  title 'Active X One-Off forms must be configured.'
  desc 'Third-party ActiveX controls are not allowed to run in one-off forms in Outlook. You can change this behavior so that Safe Controls (Microsoft Forms 2.0 controls and the Outlook Recipient and Body controls) are allowed in one-off forms, or so that all ActiveX controls are allowed to run.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security “Allow Active X One Off Forms” must be set to “Enabled: Load only Outlook Controls”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\security

Criteria: If the value AllowActiveXOneOffForms is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security “Allow Active X One Off Forms” to “Enabled: Load only Outlook Controls”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34010r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17559'
  tag rid: 'SV-33523r1_rule'
  tag stig_id: 'DTOO234 - Outlook'
  tag gtitle: 'DTOO234 - Active X One-Off Forms'
  tag fix_id: 'F-29698r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
