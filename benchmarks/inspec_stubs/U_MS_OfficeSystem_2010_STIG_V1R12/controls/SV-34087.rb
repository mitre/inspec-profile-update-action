control 'SV-34087' do
  title 'Customer-submitted templates downloads from Office.com must be disallowed.'
  desc 'This policy setting controls whether Office 2010 users can download templates from the community area of Office.com by clicking New on the Microsoft Office menu. If you enable this policy setting, Office 2010 users cannot download customer-submitted templates from Office.com.  However, access to templates posted by Microsoft and its partners are not affected.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Tools | Options | General | Web Options...  “Disable customer-submitted templates downloads from Office.com” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\internet

Criteria: If the value DisableCustomerSubmittedDownload is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Tools | Options | General | Web Options...  “Disable customer-submitted templates downloads from Office.com” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-34227r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26631'
  tag rid: 'SV-34087r1_rule'
  tag stig_id: 'DTOO312 - Office System'
  tag gtitle: 'DTOO312 - Customer-submitted templates downloads'
  tag fix_id: 'F-29917r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
