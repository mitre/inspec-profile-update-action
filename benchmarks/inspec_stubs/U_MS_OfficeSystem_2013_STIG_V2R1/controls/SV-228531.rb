control 'SV-228531' do
  title 'The Internet Fax Feature must be disabled.'
  desc 'Excel, PowerPoint, and Word users can use the Internet Fax feature to send documents to fax recipients through an Internet fax service provider. If your organization has policies that govern the time, place, or manner in which faxes are sent, this feature could help users evade those policies.
By default, Office users can use the Internet Fax feature.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Services >> Fax "Disable Internet Fax feature" to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\services\fax

If the value 'NoFax' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Services -> Fax "Disable Internet Fax feature" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30764r498871_chk'
  tag severity: 'medium'
  tag gid: 'V-228531'
  tag rid: 'SV-228531r508020_rule'
  tag stig_id: 'DTOO198'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30749r498872_fix'
  tag 'documentable'
  tag legacy: ['V-17661', 'SV-52747']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
