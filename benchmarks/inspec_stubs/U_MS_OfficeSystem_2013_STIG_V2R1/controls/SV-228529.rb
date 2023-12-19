control 'SV-228529' do
  title 'The Customer Experience Improvement Program for Office must be disabled.'
  desc "When users choose to participate in the Customer Experience Improvement Program (CEIP), Office applications automatically send information to Microsoft about how the applications are used. This information is combined with other CEIP data to help Microsoft solve problems and to improve the products and features customers use most often. This feature does not collect users' names, addresses, or any other identifying information except the IP address that is used to send the data.
By default, users have the opportunity to opt into participation in the CEIP the first time they run an Office application. If an organization has policies that govern the use of external resources such as the CEIP, allowing users to opt in to the program might cause them to violate these policies."
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Privacy >> Trust Center "Enable Customer Experience Improvement Program" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common

Criteria: If the value 'QMEnable' is REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Privacy -> Trust Center "Enable Customer Experience Improvement Program" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30762r498865_chk'
  tag severity: 'medium'
  tag gid: 'V-228529'
  tag rid: 'SV-228529r508020_rule'
  tag stig_id: 'DTOO184'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30747r498866_fix'
  tag 'documentable'
  tag legacy: ['SV-52721', 'V-17612']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
