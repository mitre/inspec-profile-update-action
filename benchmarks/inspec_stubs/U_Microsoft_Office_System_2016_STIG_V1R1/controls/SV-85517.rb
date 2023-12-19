control 'SV-85517' do
  title 'When using the Office Feedback tool, the ability to include a screenshot must be disabled.'
  desc 'This policy setting manages whether the Office Feedback Tool (a.k.a. Send a Smile) allows the user to send a screenshot of their desktop with their feedback to Microsoft. The Office Feedback Tool allows users to provide Microsoft feedback regarding their positive and negative experiences when using Office. If you enable this policy setting, the Office Feedback Tool will allow the user to send a screenshot of their desktop with their feedback to Microsoft. If you disable this policy setting, the Office Feedback Tool will not allow the user to send a screenshot of their desktop with their feedback to Microsoft. If you do not configure this policy setting, the behavior is the equivalent of setting the policy to "Enabled".'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Privacy -> Trust Center -> "Allow including screenshot with Office Feedback" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\16.0\\common\\feedback

Criteria: If the value includescreenshot is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Privacy -> Trust Center -> "Allow including screenshot with Office Feedback" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-71337r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70893'
  tag rid: 'SV-85517r1_rule'
  tag stig_id: 'DTOO410'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-77225r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
