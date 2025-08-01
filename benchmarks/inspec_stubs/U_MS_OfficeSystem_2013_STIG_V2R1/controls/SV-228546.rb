control 'SV-228546' do
  title 'The ability to create an online presentation programmatically must be disabled.'
  desc 'Allowing online presentations to be created programmatically allows for the capability of malicious content to become imbedded in those programmatically created presentations.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Present Online >> "Restrict programmatic access for creating online presentations in PowerPoint and Word" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\broadcast 

If the value 'disableprogrammaticaccess' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Present Online -> "Restrict programmatic access for creating online presentations in PowerPoint and Word" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30779r498916_chk'
  tag severity: 'medium'
  tag gid: 'V-228546'
  tag rid: 'SV-228546r508020_rule'
  tag stig_id: 'DTOO409'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-30764r498917_fix'
  tag 'documentable'
  tag legacy: ['V-40879', 'SV-53211']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
