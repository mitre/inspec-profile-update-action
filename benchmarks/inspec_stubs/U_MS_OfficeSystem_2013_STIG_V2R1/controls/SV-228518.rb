control 'SV-228518' do
  title 'A mix of policy and user locations for Office Products must be disallowed.'
  desc 'When Microsoft Office files are opened from trusted locations, all the content in the files is enabled and active. Users are not notified about any potential risks that might be contained in the files, such as unsigned macros, ActiveX controls, or links to content on the Internet.
By default, users can specify any location as a trusted location, and a computer can have a combination of user-created, OCT-created, and Group Policy–created trusted locations.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Security Settings >> Trust Center "Allow mix of policy and user locations" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\security\trusted locations

If the value 'Allow User Locations' is REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Security Settings -> Trust Center "Allow mix of policy and user locations" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30751r498832_chk'
  tag severity: 'medium'
  tag gid: 'V-228518'
  tag rid: 'SV-228518r508020_rule'
  tag stig_id: 'DTOO196'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30736r498833_fix'
  tag 'documentable'
  tag legacy: ['SV-52745', 'V-17560']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
