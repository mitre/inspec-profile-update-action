control 'SV-228525' do
  title 'When using the Office Feedback tool, the ability to include a screenshot must be disabled.'
  desc 'The "Office Feedback" tool, also called "Send-a-Smile", allows a user to click on an icon and send feedback to Microsoft. The "Office Feedback" Tool must be configured to be disabled. In the event that the Office Feedback Tool has not been configured correctly as disabled, this policy configures whether the uploading of screenshots via the tool is allowed and should also be disabled. Uploading screenshots to a commercial vendor from a DoD computer may unintentionally reveal configuration and/or FOUO content.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Privacy >> Trust Center >>"Allow including screenshot with Office Feedback" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\feedback

If the value 'includescreenshot' is REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Privacy -> Trust Center -> "Allow including screenshot with Office Feedback" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30758r498853_chk'
  tag severity: 'medium'
  tag gid: 'V-228525'
  tag rid: 'SV-228525r508020_rule'
  tag stig_id: 'DTOO410'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30743r498854_fix'
  tag 'documentable'
  tag legacy: ['V-40880', 'SV-53212']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
