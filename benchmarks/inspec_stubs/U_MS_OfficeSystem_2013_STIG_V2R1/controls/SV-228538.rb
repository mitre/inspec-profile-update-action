control 'SV-228538' do
  title 'Office Presentation Service must be removed as an option for presenting PowerPoint and Word online.'
  desc 'The Office Presentation Service is a free, public service that allows others to  follow along in a web browser. Allowing this feature could result in presentations with DoD FOUO, PII and other protected data to be viewed in a nonsecure location. By disabling this policy, the user will not have the ability to deliver a presentation online.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Present Online >> "Remove Office Presentation Service from the list of online presentation services in PowerPoint and Word" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\broadcast 

If the value 'disabledefaultservice' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Present Online -> "Remove Office Presentation Service from the list of online presentation services in PowerPoint and Word" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30771r498892_chk'
  tag severity: 'medium'
  tag gid: 'V-228538'
  tag rid: 'SV-228538r508020_rule'
  tag stig_id: 'DTOO408'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30756r498893_fix'
  tag 'documentable'
  tag legacy: ['SV-53207', 'V-40875']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
