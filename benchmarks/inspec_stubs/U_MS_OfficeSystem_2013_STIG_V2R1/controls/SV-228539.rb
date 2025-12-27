control 'SV-228539' do
  title 'The Office Feedback tool must be disabled.'
  desc 'The "Office Feedback" tool, also called "Send-a-Smile", allows a user to click on an icon and send feedback to Microsoft. Applications used by DoD users should not be able to provide feedback to commercial vendors regarding their positive and negative experiences when using Office due to the potential of unintentionally revealing FOUO or other protected content.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Privacy >> Trust Center >> "Send Office Feedback" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\feedback 

If the value 'enabled' is REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Privacy >> Trust Center >> "Send Office Feedback" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30772r498895_chk'
  tag severity: 'medium'
  tag gid: 'V-228539'
  tag rid: 'SV-228539r508020_rule'
  tag stig_id: 'DTOO411'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30757r498896_fix'
  tag 'documentable'
  tag legacy: ['V-40881', 'SV-53213']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
