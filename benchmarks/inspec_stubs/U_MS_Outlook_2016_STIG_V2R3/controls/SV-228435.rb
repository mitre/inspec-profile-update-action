control 'SV-228435' do
  title 'ActiveX One-Off forms must be configured.'
  desc 'By default, third-party ActiveX controls are not allowed to run in one-off forms in Outlook. You can change this behavior so that Safe Controls (Microsoft Forms 2.0 controls and the Outlook Recipient and Body controls) are allowed in one-off forms, or so that all ActiveX controls are allowed to run.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security "Allow Active X One Off Forms" is set to "Enabled: Load only Outlook Controls".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value AllowActiveXOneOffForms is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security "Allow Active X One Off Forms" to "Enabled: Load only Outlook Controls".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30668r497627_chk'
  tag severity: 'medium'
  tag gid: 'V-228435'
  tag rid: 'SV-228435r508021_rule'
  tag stig_id: 'DTOO234'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-30653r497628_fix'
  tag 'documentable'
  tag legacy: ['SV-85773', 'V-71149']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
