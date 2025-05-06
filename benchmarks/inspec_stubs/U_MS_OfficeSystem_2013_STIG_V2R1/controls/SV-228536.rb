control 'SV-228536' do
  title 'The ability to automatically hyperlink screenshots within Word, PowerPoint, Excel and Outlook must be disabled.'
  desc 'The ability to automatically bind hyperlink to a screenshot inserted through the Insert Screenshot tool introduces the possibility of a malicious URL or website being imbedded in the Word, PowerPoint, Excel or Outlook document. Disabling the hyperlink in those screenshots will ensure users do not have the ability to directly open the hyperlinks.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Miscellaneous >> "Do not automatically hyperlink screenshots" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\gfx 

If the value 'disablescreenshotautohyperlink' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Miscellaneous -> "Do not automatically hyperlink screenshots" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30769r498886_chk'
  tag severity: 'medium'
  tag gid: 'V-228536'
  tag rid: 'SV-228536r508020_rule'
  tag stig_id: 'DTOO406'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30754r498887_fix'
  tag 'documentable'
  tag legacy: ['SV-53195', 'V-40863']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
