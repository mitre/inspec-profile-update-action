control 'SV-85479' do
  title 'The Help Improve Proofing Tools feature for Office must be configured.'
  desc %q(This policy setting controls whether the Help Improve Proofing Tools feature sends usage data to Microsoft. The Help Improve Proofing Tools feature collects data about use of the Proofing Tools, such as additions to the custom dictionary, and sends it to Microsoft. After about six months, the feature stops sending data to Microsoft and deletes the data collection file from the user's computer. If you enable this policy setting, this feature is enabled if users choose to participate in the Customer Experience Improvement Program (CEIP). If your organization has policies that govern the use of external resources such as the CEIP, allowing the use of the Help Improve Proofing Tools feature might cause them to violate these policies. If you disable this policy setting, the Help Improve Proofing Tools feature does not collect proofing tool usage information and transmit it to Microsoft. If you do not configure this policy setting, the behavior is the equivalent of setting the policy to "Enabled".)
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Tools \\ Options \\ Spelling -> Proofing Data Collection "Improve Proofing Tools" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\common\\ptwatson

Criteria: If the value PTWOptIn is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Tools \\ Options \\ Spelling -> Proofing Data Collection "Improve Proofing Tools" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-71299r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70855'
  tag rid: 'SV-85479r1_rule'
  tag stig_id: 'DTOO182'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-77187r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
