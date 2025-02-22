control 'SV-33481' do
  title 'The Help Improve Proofing Tools feature for Office must be configured.'
  desc "The Help Improve Proofing Tools feature collects data about use of the Proofing Tools, such as additions to the custom dictionary, and sends it to Microsoft. After about six months, the feature stops sending data to Microsoft and deletes the data collection file from the user's computer. Although this feature does not intentionally collect personal information, some of the content sent could include items that were marked as spelling or grammar errors, such as proper names and account numbers. However, any numbers such as account numbers, street addresses, and phone numbers are converted to zeroes when the data is collected. Microsoft uses this information solely to improve the effectiveness of the Office Proofing Tools, not to identify users.
By default, this feature is enabled, if users choose to participate in the Customer Experience Improvement Program (CEIP). If your organization has policies that govern the use of external resources such as the CEIP, allowing the use of the Help Improve Proofing Tools feature might cause them to violate these policies."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Tools \\ Options \\ Spelling -> Proofing Data Collection “Improve Proofing Tools” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\ptwatson

Criteria: If the value PTWOptIn is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Tools \\ Options \\ Spelling -> Proofing Data Collection “Improve Proofing Tools” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33964r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17627'
  tag rid: 'SV-33481r1_rule'
  tag stig_id: 'DTOO182 - Office System'
  tag gtitle: 'DTOO182 - Improve Proofing Tools'
  tag fix_id: 'F-29653r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
